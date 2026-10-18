//! Closed T0/T1/G/E0/E1 reads and F freshness on the already-held interval.

use super::SqliteStore;
use crate::{
    fork_replay::{
        corrupt, gate_error, remember_member, LineageReadContextV1, LineageReadResult as ReadResult,
    },
    ForkReplayAuthorityReadErrorV1 as ReadError, ForkReplayLineageNodeV1,
    ForkReplayLineageReadErrorV1 as Error,
};
use pos_core::{ErasureGate, ErasureProtectedOperationV1, Seq, TimelineId};
use rusqlite::{params, types::FromSql, types::ValueRef, Params, Row};

const STORAGE_ERROR: Error = Error::Read(ReadError::StorageUnavailable);

fn get<T: FromSql>(
    row: &Row<'_>,
    column: usize,
    context: &mut LineageReadContextV1<'_, '_>,
) -> ReadResult<T> {
    context.step(|_| row.get(column).map_err(|_| STORAGE_ERROR))
}

fn integer(
    row: &Row<'_>,
    column: usize,
    context: &mut LineageReadContextV1<'_, '_>,
) -> ReadResult<i64> {
    context.step(|_| match row.get_ref(column).map_err(|_| STORAGE_ERROR)? {
        ValueRef::Integer(value) => Ok(value),
        _ => corrupt(),
    })
}

fn parse_id(text: &str, context: &mut LineageReadContextV1<'_, '_>) -> ReadResult<TimelineId> {
    // Use the ordinary native owner's pinned ULID parser, without constructing
    // its formatted CoreError String only to discard that diagnostic.
    context.step(|_| {
        text.parse::<ulid::Ulid>()
            .map(TimelineId::from_ulid)
            .map_err(|_| Error::Read(ReadError::CorruptAuthority))
    })
}

fn text(
    row: &Row<'_>,
    column: usize,
    length: usize,
    context: &mut LineageReadContextV1<'_, '_>,
) -> ReadResult<String> {
    context.step(|context| {
        context.step(|_| match row.get_ref(column).map_err(|_| STORAGE_ERROR)? {
            ValueRef::Text(bytes)
                if bytes.len() == length && std::str::from_utf8(bytes).is_ok() =>
            {
                Ok(())
            }
            _ => corrupt(),
        })?;
        context.bytes(length)?;
        get(row, column, context)
    })
}

impl SqliteStore {
    /// EOF checks the clock but charges no fictitious row. An actual row is
    /// debited before its first getter, even at zero remaining row capacity.
    pub(super) fn lineage_row<T>(
        &self,
        sql: &str,
        params: impl Params,
        context: &mut LineageReadContextV1<'_, '_>,
        read: impl FnOnce(&Row<'_>, &mut LineageReadContextV1<'_, '_>) -> ReadResult<T>,
    ) -> ReadResult<Option<T>> {
        context.step(|context| {
            let mut statement =
                context.step(|_| self.conn.prepare(sql).map_err(|_| STORAGE_ERROR))?;
            let mut rows = context.step(|_| statement.query(params).map_err(|_| STORAGE_ERROR))?;
            let row = context.step(|_| rows.next().map_err(|_| STORAGE_ERROR))?;
            if let Some(row) = row {
                context.row()?;
                read(row, context).map(Some)
            } else {
                Ok(None)
            }
        })
    }

    fn lineage_freshness(
        &self,
        gate: &pos_core::ErasureContainmentGateV1,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<()> {
        context.step(|context| {
            if !self.erasure_gate_bound {
                return Ok(());
            }
            let observed = self
                .lineage_row("PRAGMA data_version", [], context, |row, context| {
                    integer(row, 0, context)
                })
                // The enclosing step post-check preserves every latched
                // budget refusal before returning this native-error mapping.
                .map_err(|_| Error::ContainmentUnavailable)?;
            if observed != Some(self.erasure_inventory_data_version) {
                return Err(Error::ContainmentUnavailable);
            }
            context.step(|_| {
                crate::validate_bound_erasure_inventory_generation(
                    true,
                    gate,
                    self.erasure_inventory_generation,
                )
                .map_err(|_| Error::ContainmentUnavailable)
            })
        })
    }

    pub(super) fn read_lineage_member(
        &self,
        timeline: TimelineId,
        visited: &mut Vec<TimelineId>,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>> {
        self.with_replay_read_fence(timeline, context, |context| {
            self.lineage_metadata_and_visibility(timeline, visited, context)
        })
    }

    pub(super) fn with_replay_read_fence<T>(
        &self,
        timeline: TimelineId,
        context: &mut LineageReadContextV1<'_, '_>,
        mut effect: impl FnMut(&mut LineageReadContextV1<'_, '_>) -> ReadResult<T>,
    ) -> ReadResult<T> {
        context.step(|context| {
            let gate = self
                .erasure_gate
                .as_deref()
                .ok_or(Error::ContainmentUnavailable)?;
            self.lineage_freshness(gate, context)?;
            let mut result = Err(Error::ContainmentUnavailable);
            let fenced = gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
                result = effect(context);
            });
            // A latched refusal stops semantic work. Otherwise completion F
            // still executes after a native None/error or a gate denial.
            context.check()?;
            self.lineage_freshness(gate, context)?;
            fenced.map_err(gate_error).and(result)
        })
    }

    fn lineage_metadata_and_visibility(
        &self,
        timeline: TimelineId,
        visited: &mut Vec<TimelineId>,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<Option<(ForkReplayLineageNodeV1, Seq)>> {
        context.step(|context| {
            remember_member(timeline, visited, context)?;
            context.bytes(26)?;
            let key = timeline.to_string();
            context.check()?;
            let shape = self.lineage_row(
                "SELECT typeof(id)='text' AND length(CAST(id AS BLOB))=26,
                        parent_id IS NULL AND fork_seq IS NULL,
                        typeof(parent_id)='text' AND length(CAST(parent_id AS BLOB))=26
                            AND typeof(fork_seq)='integer' AND fork_seq>=0,
                        typeof(head_seq)='integer' AND head_seq>=0
                 FROM timelines WHERE id=?1",
                [&key],
                context,
                |row, context| {
                    let valid_id: bool = get(row, 0, context)?;
                    let root: bool = get(row, 1, context)?;
                    let fork: bool = get(row, 2, context)?;
                    let valid_head: bool = get(row, 3, context)?;
                    if valid_id && valid_head && (root || fork) {
                        Ok(fork)
                    } else {
                        corrupt()
                    }
                },
            )?;
            let Some(fork) = shape else {
                return if visited.len() == 1 {
                    Ok(None)
                } else {
                    corrupt()
                };
            };
            let metadata = self
                .lineage_row(
                    "SELECT id,parent_id,fork_seq,head_seq FROM timelines WHERE id=?1",
                    [&key],
                    context,
                    |row, context| Self::lineage_fields(row, timeline, fork, context),
                )?
                .ok_or(Error::Read(ReadError::CorruptAuthority))?;
            if self
                .lineage_row(
                    "SELECT 1 FROM geographic_presence WHERE timeline_id=?1",
                    [&key],
                    context,
                    |_, _| Ok(()),
                )?
                .is_some()
                || self.lineage_geographic_events(&key, context)?
            {
                Ok(None)
            } else {
                Ok(Some(metadata))
            }
        })
    }

    fn lineage_fields(
        row: &Row<'_>,
        timeline: TimelineId,
        fork: bool,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<(ForkReplayLineageNodeV1, Seq)> {
        context.step(|context| {
            let id = text(row, 0, 26, context)?;
            let id = parse_id(&id, context)?;
            if id != timeline {
                return corrupt();
            }
            let fork_point = if fork {
                let parent = text(row, 1, 26, context)?;
                let parent = parse_id(&parent, context)?;
                let cut = integer(row, 2, context)?;
                Some((
                    parent,
                    u64::try_from(cut).map_err(|_| Error::Read(ReadError::CorruptAuthority))?,
                ))
            } else {
                for column in [1, 2] {
                    context.step(|_| match row.get_ref(column).map_err(|_| STORAGE_ERROR)? {
                        ValueRef::Null => Ok(()),
                        _ => corrupt(),
                    })?;
                }
                None
            };
            let head = integer(row, 3, context)?;
            let head = u64::try_from(head).map_err(|_| Error::Read(ReadError::CorruptAuthority))?;
            context.bytes(if fork { 49 } else { 25 })?;
            let node = ForkReplayLineageNodeV1::new(
                id,
                fork_point.map(|(parent, cut)| (parent, Seq::from_u64(cut))),
            );
            Ok((node, Seq::from_u64(head)))
        })
    }

    fn lineage_geographic_events(
        &self,
        key: &str,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> ReadResult<bool> {
        context.step(|context| {
            let mut cursor = None;
            loop {
                let read = |row: &Row<'_>, context: &mut LineageReadContextV1<'_, '_>| {
                    let sequence = integer(row, 0, context)?;
                    let valid_type: bool = get(row, 1, context)?;
                    let length = integer(row, 2, context)?;
                    if sequence <= 0
                        || cursor.is_some_and(|cursor| sequence <= cursor)
                        || !valid_type
                        || length < 0
                    {
                        return corrupt();
                    }
                    context.bytes(8)?;
                    Ok((sequence, length))
                };
                let candidate = if let Some(cursor) = cursor {
                    self.lineage_row(
                        "SELECT seq,typeof(event_type)='text',length(CAST(event_type AS BLOB))
                         FROM events WHERE timeline_id=?1 AND seq>?2 ORDER BY seq LIMIT 1",
                        params![key, cursor],
                        context,
                        read,
                    )?
                } else {
                    self.lineage_row(
                        "SELECT seq,typeof(event_type)='text',length(CAST(event_type AS BLOB))
                         FROM events WHERE timeline_id=?1 ORDER BY seq LIMIT 1",
                        [key],
                        context,
                        read,
                    )?
                };
                let Some((sequence, length)) = candidate else {
                    return Ok(false);
                };
                cursor = Some(sequence);
                if let Ok(length @ (8 | 12)) = usize::try_from(length) {
                    let kind = self
                        .lineage_row(
                            "SELECT event_type FROM events WHERE timeline_id=?1 AND seq=?2",
                            params![key, sequence],
                            context,
                            |row, context| text(row, 0, length, context),
                        )?
                        .ok_or(Error::Read(ReadError::CorruptAuthority))?;
                    if context.step(|_| {
                        Ok(kind == pos_core::GEOGRAPHIC_EVENT_TYPE
                            || kind == pos_core::GEOGRAPHIC_CELL_EVENT_TYPE)
                    })? {
                        return Ok(true);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
        ErasureProtectedEffectDispositionV1, EventDraft, EventStore, Kind,
    };
    use std::{sync::Arc, time::Duration};

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> Fallible<(SqliteStore, TimelineId, TimelineId)> {
        let mut store = SqliteStore::open(":memory:")?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("lineage fault root")?.id();
        drop(store.append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("ordinary"),
                CanonicalBytes::from_static(b"not read by lineage"),
            )],
        )?);
        let child = store
            .fork(root, Seq::from_u64(1), "lineage fault child")?
            .id();
        // Only impossible-state storage fixtures bypass CHECKs; the reader
        // still crosses its actual public port and the normal installed gate.
        store
            .conn
            .execute_batch("PRAGMA ignore_check_constraints=ON")?;
        Ok((store, root, child))
    }

    type ReadTranscript = Arc<std::sync::Mutex<Vec<(String, String, bool)>>>;

    fn redact_read(conn: &rusqlite::Connection, ordinal: usize) -> Fallible<ReadTranscript> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

        let transcript = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = Arc::clone(&transcript);
        conn.authorizer(Some(move |request: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = request.action
            {
                let Ok(mut reads) = observed.lock() else {
                    return Authorization::Deny;
                };
                let ignored = reads.len() == ordinal;
                reads.push((table_name.to_owned(), column_name.to_owned(), ignored));
                if ignored {
                    return Authorization::Ignore;
                }
            }
            Authorization::Allow
        }))?;
        Ok(transcript)
    }

    fn assert_reads(
        transcript: &ReadTranscript,
        table: &str,
        columns: &[&str],
        ignored: usize,
    ) -> Fallible<()> {
        let reads = transcript.lock().map_err(|_| "read observer poisoned")?;
        let actual: Vec<_> = reads
            .iter()
            .map(|(table, column, ignored)| (table.as_str(), column.as_str(), *ignored))
            .collect();
        let expected: Vec<_> = columns
            .iter()
            .enumerate()
            .map(|(index, column)| (table, *column, index == ignored))
            .collect();
        assert_eq!(actual, expected);
        drop(reads);
        Ok(())
    }

    #[test]
    fn metadata_where_redaction_refuses_only_the_raw_fetch_and_preserves_debits() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        let (store, root, _) = fixture()?;
        let interval = store.begin_protected_effect_interval()?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        // Failure: visited ID16 + key26, one shape row. Healthy root:
        // 42 + metadata51 + candidate8 + ordinary-kind8, four real rows.
        let limits = ForkReplayReadLimitsV1::new(8, 2, 5, 151, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        // Eleven shape reads, then four projected metadata fields and WHERE id.
        let observed = redact_read(&store.conn, 15)?;
        let failed = store.lineage_metadata_and_visibility(
            root,
            &mut Vec::new(),
            &mut LineageReadContextV1::new(&mut budget, 8)?,
        );
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        assert_reads(
            &observed,
            "timelines",
            &[
                "id",
                "id",
                "parent_id",
                "fork_seq",
                "parent_id",
                "parent_id",
                "fork_seq",
                "fork_seq",
                "head_seq",
                "head_seq",
                "id",
                "id",
                "parent_id",
                "fork_seq",
                "head_seq",
                "id",
            ],
            15,
        )?;
        assert_eq!(failed, Err(Error::Read(ReadError::CorruptAuthority)));
        assert_eq!(budget.remaining_native_bytes(), 109);
        budget.check_time()?;
        assert_eq!(
            store.lineage_metadata_and_visibility(
                root,
                &mut Vec::new(),
                &mut LineageReadContextV1::new(&mut budget, 8)?,
            )?,
            Some((ForkReplayLineageNodeV1::new(root, None), Seq::from_u64(1)))
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        budget.check_time()?;
        assert!(budget.charge_rows(1).is_err());
        assert!(budget.check_time().is_err());
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        assert!(store.conn.is_autocommit());
        Ok(())
    }

    #[test]
    fn geographic_where_redaction_refuses_only_the_raw_kind_and_preserves_debits() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        let (store, root, _) = fixture()?;
        let key = root.to_string();
        let interval = store.begin_protected_effect_interval()?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        // Failure: one candidate row/8 bytes. Healthy: candidate + raw row,
        // 8 descriptor + 8 ordinary-kind bytes; final EOF charges no row.
        let limits = ForkReplayReadLimitsV1::new(8, 1, 3, 24, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        // Five candidate reads, raw event_type, then the raw WHERE timeline key.
        let observed = redact_read(&store.conn, 6)?;
        let failed =
            store.lineage_geographic_events(&key, &mut LineageReadContextV1::new(&mut budget, 8)?);
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        assert_reads(
            &observed,
            "events",
            &[
                "seq",
                "event_type",
                "event_type",
                "timeline_id",
                "seq",
                "event_type",
                "timeline_id",
                "seq",
            ],
            6,
        )?;
        assert_eq!(failed, Err(Error::Read(ReadError::CorruptAuthority)));
        assert_eq!(budget.remaining_native_bytes(), 16);
        budget.check_time()?;
        assert!(!store
            .lineage_geographic_events(&key, &mut LineageReadContextV1::new(&mut budget, 8)?,)?);
        assert_eq!(budget.remaining_native_bytes(), 0);
        budget.check_time()?;
        assert!(budget.charge_rows(1).is_err());
        assert!(budget.check_time().is_err());
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        assert!(store.conn.is_autocommit());
        Ok(())
    }

    fn read(
        store: &SqliteStore,
        timeline: TimelineId,
        clock: &mut dyn GuardMonotonicSourceV1,
    ) -> Fallible<ReadResult<Option<ForkReplayLineageNodeV1>>> {
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, clock)?;
        let interval = store.begin_protected_effect_interval()?;
        let result = store.read_fork_replay_lineage_node(timeline, 0, 8, &mut budget);
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        Ok(result)
    }

    #[test]
    fn public_lineage_refuses_redacted_shape_before_fetching_metadata() -> Fallible<()> {
        use rusqlite::hooks::{AuthContext, Authorization};

        for ignored in [0, 8] {
            let (store, root, child) = fixture()?;
            for (timeline, expected) in [
                (root, ForkReplayLineageNodeV1::new(root, None)),
                (
                    child,
                    ForkReplayLineageNodeV1::new(child, Some((root, Seq::from_u64(1)))),
                ),
            ] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let healthy = Ok(Some(expected));
                assert_eq!(read(&store, timeline, &mut clock)?, healthy);
                // Redact only the shape probe's typeof(id) or typeof(head_seq).
                // The stored row and later metadata projection remain healthy:
                // rejecting it must not depend on that second decoder barrier.
                let observed = redact_read(&store.conn, ignored)?;
                let failed = read(&store, timeline, &mut clock)?;
                store
                    .conn
                    .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
                assert_eq!(failed, Err(Error::Read(ReadError::CorruptAuthority)));
                assert_reads(
                    &observed,
                    "timelines",
                    &[
                        "id",
                        "id",
                        "parent_id",
                        "fork_seq",
                        "parent_id",
                        "parent_id",
                        "fork_seq",
                        "fork_seq",
                        "head_seq",
                        "head_seq",
                        "id",
                    ],
                    ignored,
                )?;
                assert_eq!(read(&store, timeline, &mut clock)?, healthy);
                assert!(store.conn.is_autocommit());
            }
        }
        Ok(())
    }

    #[test]
    fn descending_nested_fork_cut_refuses_the_public_logical_head() -> Fallible<()> {
        let (mut store, _, child) = fixture()?;
        let nested = store.fork(child, Seq::from_u64(1), "nested lineage")?.id();
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        // Both Forks initially inherit the root's one Event. A nested cut of
        // zero contradicts the child's inherited prefix of one, even though
        // each native metadata row remains individually well-formed.
        for (cut, expected) in [
            (1_i64, Ok(Seq::from_u64(1))),
            (0, Err(Error::Read(ReadError::CorruptAuthority))),
            (1, Ok(Seq::from_u64(1))),
        ] {
            assert_eq!(
                store.conn.execute(
                    "UPDATE timelines SET fork_seq=?1 WHERE id=?2",
                    params![cut, nested.to_string()],
                )?,
                1
            );
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let interval = store.begin_protected_effect_interval()?;
            assert_eq!(
                store.fork_replay_logical_head(nested, 8, &mut budget),
                expected
            );
            // Corrupt stored coordinates are not a failed resource debit.
            budget.check_time()?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
            assert!(store.conn.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn native_lineage_decoder_refuses_short_projections_without_refunding_work() -> Fallible<()> {
        // Production statements supply all four columns. Like the independent
        // identity/root-shape defenses below, these real SQL projections test
        // the existing decoder's second barrier, not public query reachability.
        for (sql, fork) in [
            ("SELECT id FROM timelines WHERE id=?1", true),
            ("SELECT id,NULL FROM timelines WHERE id=?1", false),
            ("SELECT id,NULL,NULL FROM timelines WHERE id=?1", false),
        ] {
            let (store, root, _) = fixture()?;
            let interval = store.begin_protected_effect_interval()?;
            let key = root.to_string();
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            // Both reads debit a real row. Failure has already materialized
            // the 26-byte ID; the healthy root then charges 26+25 bytes.
            let limits = ForkReplayReadLimitsV1::new(8, 1, 2, 77, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let failed = store.lineage_row(
                sql,
                [&key],
                &mut LineageReadContextV1::new(&mut budget, 8)?,
                |row, context| SqliteStore::lineage_fields(row, root, fork, context),
            );
            assert_eq!(failed, Err(STORAGE_ERROR));
            assert_eq!(budget.remaining_native_bytes(), 51);
            budget.check_time()?;
            assert_eq!(
                store.lineage_row(
                    "SELECT id,parent_id,fork_seq,head_seq FROM timelines WHERE id=?1",
                    [&key],
                    &mut LineageReadContextV1::new(&mut budget, 8)?,
                    |row, context| SqliteStore::lineage_fields(row, root, false, context),
                )?,
                Some((ForkReplayLineageNodeV1::new(root, None), Seq::from_u64(1)))
            );
            assert_eq!(budget.remaining_native_bytes(), 0);
            budget.check_time()?;
            assert!(budget.charge_rows(1).is_err());
            assert!(budget.check_time().is_err());
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
            assert!(store.conn.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn native_lineage_decoder_binds_selected_identity_and_root_shape() -> Fallible<()> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let target = TimelineId::new();
        let other = TimelineId::new();
        // Real SQL rows deliberately violate selection/classification promises.
        // A coherent held snapshot cannot do this; these are independent
        // decoder defenses, not a simulated concurrent public Store mutation.
        for (selected, parent, cut, head, fork, expected, bytes) in [
            (
                target,
                None,
                None,
                1_i64,
                false,
                Ok((ForkReplayLineageNodeV1::new(target, None), Seq::from_u64(1))),
                51,
            ),
            (
                target,
                Some(other),
                Some(1_i64),
                1,
                true,
                Ok((
                    ForkReplayLineageNodeV1::new(target, Some((other, Seq::from_u64(1)))),
                    Seq::from_u64(1),
                )),
                101,
            ),
            (
                other,
                None,
                None,
                1,
                false,
                Err(Error::Read(ReadError::CorruptAuthority)),
                26,
            ),
            (
                target,
                Some(other),
                None,
                1,
                false,
                Err(Error::Read(ReadError::CorruptAuthority)),
                26,
            ),
            (
                target,
                None,
                Some(1),
                1,
                false,
                Err(Error::Read(ReadError::CorruptAuthority)),
                26,
            ),
            (
                target,
                Some(other),
                Some(-1),
                1,
                true,
                Err(Error::Read(ReadError::CorruptAuthority)),
                52,
            ),
            (
                target,
                None,
                None,
                -1,
                false,
                Err(Error::Read(ReadError::CorruptAuthority)),
                26,
            ),
        ] {
            let mut statement = conn.prepare("SELECT ?1, ?2, ?3, ?4")?;
            let mut rows = statement.query(params![
                selected.to_string(),
                parent.map(|id| id.to_string()),
                cut,
                head,
            ])?;
            let row = rows.next()?.ok_or("missing native lineage row")?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let result = SqliteStore::lineage_fields(
                row,
                target,
                fork,
                &mut LineageReadContextV1::new(&mut budget, 8)?,
            );
            assert_eq!(result, expected);
            // Decoding charges the actual ID Strings before the fixed native
            // coordinate: root 26+25, Fork 26+26+49. The negative cut stops
            // after both IDs (52); all other faults stop after the first (26).
            assert_eq!(budget.remaining_native_bytes(), 16_384 - bytes);
            budget.check_time()?;
        }
        Ok(())
    }

    #[test]
    fn removing_a_bound_gate_refuses_held_reads_and_new_intervals() -> Fallible<()> {
        let mut store = SqliteStore::open(":memory:")?;
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("removed lineage gate")?.id();
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let interval = store.begin_fork_replay_read_interval(&mut budget)?;
        let healthy = store.read_fork_replay_lineage_node(root, 0, 8, &mut budget);
        let remaining = budget.remaining_native_bytes();

        // The public consuming operation removes the gate without changing the
        // held native transaction. No private-field fault injection is needed.
        let store = store.without_erasure_gate();
        let refused_read = store.read_fork_replay_lineage_node(root, 0, 8, &mut budget);
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        assert!(healthy?.is_some());
        assert_eq!(refused_read, Err(Error::ContainmentUnavailable));
        assert_eq!(budget.remaining_native_bytes(), remaining);
        budget.check_time()?;
        assert!(store.conn.is_autocommit());

        // A fresh begin reaches the bound-gate check after acquiring its native
        // interval and must unwind that acquisition on the same healthy ledger.
        assert_eq!(
            store.begin_fork_replay_read_interval(&mut budget),
            Err(Error::ContainmentUnavailable)
        );
        assert!(store.conn.is_autocommit());
        assert_eq!(budget.remaining_native_bytes(), remaining);
        budget.check_time()?;
        Ok(())
    }

    #[test]
    fn unbound_lineage_is_refused_by_the_default_gate_before_metadata_reads() -> Fallible<()> {
        let mut store = SqliteStore::open(":memory:")?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let interval = store.begin_fork_replay_read_interval(&mut budget)?;
        assert_eq!(
            store.read_fork_replay_lineage_node(TimelineId::new(), 0, 8, &mut budget),
            Err(Error::ContainmentUnavailable)
        );
        assert_eq!(budget.remaining_native_bytes(), 16_384);
        budget.check_time()?;
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        assert!(store.conn.is_autocommit());
        // The default closed gate, not poisoned connections or an expired
        // ledger, prevented the read. Normal binding permits a real root.
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        let root = store.create_timeline("bound lineage control")?.id();
        assert!(read(&store, root, &mut clock)??.is_some());
        Ok(())
    }

    #[test]
    fn malformed_native_metadata_and_event_rows_fail_through_the_public_port() -> Fallible<()> {
        for sql in [
            "UPDATE timelines SET parent_id=NULL WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET fork_seq=NULL WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET parent_id='not-an-id' WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET parent_id='ZZZZZZZZZZZZZZZZZZZZZZZZZZ' WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET fork_seq=-1 WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET head_seq=-1 WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET head_seq='invalid' WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET parent_id=id,fork_seq=0 WHERE parent_id IS NOT NULL",
            "UPDATE timelines SET parent_id='00000000000000000000000000' WHERE parent_id IS NOT NULL",
            "UPDATE events SET seq=0",
            "UPDATE events SET seq=-1",
            "UPDATE events SET seq='invalid'",
            "UPDATE events SET event_type=x'00'",
        ] {
            let (store, _, child) = fixture()?;
            store.conn.execute_batch(sql)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            assert_eq!(
                read(&store, child, &mut clock)?,
                Err(Error::Read(ReadError::CorruptAuthority)),
                "{sql}"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_parent_ulid_refuses_after_native_type_and_length_checks() -> Fallible<()> {
        let invalid = "IIIIIIIIIIIIIIIIIIIIIIIIII";
        assert_eq!(invalid.len(), ulid::ULID_LEN);
        assert!(invalid.parse::<ulid::Ulid>().is_err());
        let (store, _, child) = fixture()?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        assert!(read(&store, child, &mut clock)??.is_some());
        // Valid TEXT width passes the shape query; only ULID decoding refuses.
        // Keep the original all-Z missing-parent case: Z is valid base32 here.
        assert_eq!(
            store.conn.execute(
                "UPDATE timelines SET parent_id=?1 WHERE id=?2",
                params![invalid, child.to_string()],
            )?,
            1
        );
        assert_eq!(
            read(&store, child, &mut clock)?,
            Err(Error::Read(ReadError::CorruptAuthority))
        );
        Ok(())
    }

    #[test]
    fn invalid_utf8_text_is_refused_before_native_string_materialization() -> Fallible<()> {
        for sql in [
            "UPDATE timelines SET parent_id=CAST(x'ff' || zeroblob(25) AS TEXT) WHERE parent_id IS NOT NULL",
            "UPDATE events SET event_type=CAST(x'ff' || zeroblob(7) AS TEXT)",
        ] {
            let (store, _, child) = fixture()?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            assert!(read(&store, child, &mut clock)??.is_some());
            // These retain the native TEXT type and exact byte width, so
            // refusal must come from the UTF-8 check, not the shape probe.
            store.conn.execute_batch(sql)?;
            assert_eq!(
                read(&store, child, &mut clock)?,
                Err(Error::Read(ReadError::CorruptAuthority)),
                "accepted invalid UTF-8: {sql}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_empty_opaque_event_kind_remains_visible_to_public_lineage() -> Fallible<()> {
        let (mut store, root, _) = fixture()?;
        let appended = store.append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new(""),
                CanonicalBytes::from_static(b"ordinary empty-kind payload"),
            )],
        )?;
        assert_eq!(appended.len(), 1);
        assert_eq!(appended[0].event_type.as_str(), "");
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        assert_eq!(
            read(&store, root, &mut clock)?,
            Ok(Some(ForkReplayLineageNodeV1::new(root, None)))
        );
        Ok(())
    }

    #[test]
    fn late_ancestor_presence_and_geographic_events_hide_the_entire_use() -> Fallible<()> {
        for presence in [true, false] {
            for kind in ["geo.cell", "geo.location"] {
                let (store, root, child) = fixture()?;
                if presence {
                    store.conn.execute(
                        "INSERT INTO geographic_presence(timeline_id,has_evidence) VALUES(?1,0)",
                        [root.to_string()],
                    )?;
                } else {
                    store
                        .conn
                        .execute("UPDATE events SET event_type=?1", [kind])?;
                }
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                assert_eq!(read(&store, child, &mut clock)?, Ok(None));
            }
        }
        Ok(())
    }

    #[test]
    fn original_epoch_covers_the_complete_geographic_visibility_scan() -> Fallible<()> {
        let (store, root, _) = fixture()?;
        // The ordinary eight-byte kind requires the same funded native String
        // read and comparison as a geographic candidate, but must stay visible.
        for regression in [false, true] {
            let initial = if regression {
                Duration::from_micros(1)
            } else {
                Duration::ZERO
            };
            let later = if regression {
                Duration::ZERO
            } else {
                Duration::from_secs(2)
            };
            let mut failures = 0;
            let mut completed = false;
            // Check each clock boundary through the first complete success;
            // the ceiling prevents an accidental unbounded fixture loop.
            for marks in 2..=512 {
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(initial, marks).chain([later]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let interval = store.begin_protected_effect_interval()?;
                let result = store.read_fork_replay_lineage_node(root, 0, 8, &mut budget);
                store.finish_protected_effect_interval(
                    interval,
                    ErasureProtectedEffectDispositionV1::Rollback,
                )?;
                assert!(store.conn.is_autocommit());
                match result {
                    Err(Error::Read(ReadError::BoundsExceeded)) => {
                        failures += 1;
                        assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
                    }
                    Ok(Some(node)) => {
                        assert_eq!(node.timeline_id(), &root);
                        completed = true;
                        break;
                    }
                    result => {
                        return Err(format!("unexpected visibility result: {result:?}").into())
                    }
                }
            }
            assert!(failures > 0);
            assert!(completed);
        }
        Ok(())
    }

    #[test]
    fn original_epoch_expiry_takes_precedence_over_native_storage_faults() -> Fallible<()> {
        let (store, _, child) = fixture()?;
        store.conn.execute_batch("DROP TABLE geographic_presence")?;
        let mut bounds = 0;
        let mut storage = 0;
        for marks in 2..256 {
            let mut clock = ScriptedGuardMonotonicSourceV1::new(
                std::iter::repeat_n(Duration::ZERO, marks).chain([Duration::from_secs(2)]),
            );
            match read(&store, child, &mut clock)? {
                Err(Error::Read(ReadError::BoundsExceeded)) => bounds += 1,
                Err(Error::Read(ReadError::StorageUnavailable)) => storage += 1,
                result => return Err(format!("unexpected native fault result: {result:?}").into()),
            }
        }
        assert!(bounds > 0);
        assert!(storage > 0);
        Ok(())
    }

    #[test]
    fn freshness_query_row_refusal_preserves_the_original_budget_error() -> Fallible<()> {
        let (store, _, _) = fixture()?;
        let gate = store.erasure_gate.as_deref().ok_or("bound gate")?;
        let interval = store.begin_protected_effect_interval()?;
        for (rows, succeeds) in [(1, false), (2, true)] {
            let limits = ForkReplayReadLimitsV1::new(8, 1, rows, 1, 1_000_000)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            budget.charge_rows(1)?;
            let result =
                store.lineage_freshness(gate, &mut LineageReadContextV1::new(&mut budget, 8)?);
            if succeeds {
                result?;
                budget.check_time()?;
            } else {
                assert_eq!(result, Err(Error::Read(ReadError::BoundsExceeded)));
                assert_eq!(budget.check_time(), Err(ReadError::BoundsExceeded));
            }
            // One actual PRAGMA row exhausts the healthy boundary as well;
            // skipping the native query cannot satisfy this positive control.
            assert_eq!(budget.charge_rows(1), Err(ReadError::BoundsExceeded));
        }
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        Ok(())
    }

    #[test]
    fn either_actual_gate_freshness_query_can_refuse_without_releasing_a_node() -> Fallible<()> {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use std::sync::atomic::{AtomicUsize, Ordering};

        for refused in [1, 2] {
            let (store, root, _) = fixture()?;
            let interval = store.begin_protected_effect_interval()?;
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            store
                .conn
                .authorizer(Some(move |context: AuthContext<'_>| {
                    if let AuthAction::Pragma { pragma_name, .. } = context.action {
                        if pragma_name.eq_ignore_ascii_case("data_version")
                            && observed.fetch_add(1, Ordering::SeqCst) + 1 == refused
                        {
                            return Authorization::Deny;
                        }
                    }
                    Authorization::Allow
                }))?;
            let limits = ForkReplayReadLimitsV1::new(8, 8, 64, 4_096, 1_000_000)?;
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                store.read_fork_replay_lineage_node(root, 0, 0, &mut budget),
                Err(Error::ContainmentUnavailable)
            );
            assert_eq!(calls.load(Ordering::SeqCst), refused);
            store
                .conn
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
        }
        Ok(())
    }

    fn complete_events(
        store: &SqliteStore,
        timeline: TimelineId,
    ) -> Fallible<ReadResult<Vec<pos_core::Event>>> {
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let bounds = pos_core::EventReadBounds::new_with_total_bytes_and_elapsed(
            128, 128, 8, 4, 1_024, 1_000_000,
        );
        let interval = store.begin_protected_effect_interval()?;
        let result =
            store.read_fork_replay_events(timeline, pos_core::SeqRange::all(), bounds, &mut budget);
        store.finish_protected_effect_interval(
            interval,
            ErasureProtectedEffectDispositionV1::Rollback,
        )?;
        Ok(result)
    }

    #[test]
    fn complete_event_cursor_reads_the_maximum_native_coordinate_and_stops() -> Fallible<()> {
        let (store, root, _) = fixture()?;
        let maximum = i64::MAX.unsigned_abs();
        // A sparse native boundary fixture, not a claim to contain all earlier
        // Events. The complete reader must validate exactly the requested range.
        assert_eq!(
            store.conn.execute(
                "UPDATE events SET seq=?1, origin_logical_seq=?1 WHERE timeline_id=?2",
                params![i64::MAX, root.to_string()],
            )?,
            1
        );
        assert_eq!(
            store.conn.execute(
                "UPDATE timelines SET head_seq=?1 WHERE id=?2",
                params![i64::MAX, root.to_string()],
            )?,
            1
        );
        let limits = ForkReplayReadLimitsV1::new(8, 128, 512, 16_384, 1_000_000)?;
        let bounds = pos_core::EventReadBounds::new_with_total_bytes_and_elapsed(
            128, 128, 8, 4, 1_024, 1_000_000,
        );
        for (from, to, error) in [
            (maximum, maximum, None),
            (maximum - 1, maximum, Some(ReadError::CorruptAuthority)),
            (maximum, maximum + 1, Some(ReadError::Unavailable)),
            (maximum, maximum, None),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let interval = store.begin_protected_effect_interval()?;
            let result = store.read_fork_replay_events(
                root,
                pos_core::SeqRange::bounded(Seq::from_u64(from), Seq::from_u64(to)),
                bounds,
                &mut budget,
            );
            store.finish_protected_effect_interval(
                interval,
                ErasureProtectedEffectDispositionV1::Rollback,
            )?;
            budget.check_time()?;
            if let Some(error) = error {
                assert_eq!(result, Err(Error::Read(error)));
            } else {
                let events = result?;
                assert_eq!(events.len(), 1);
                assert_eq!(events[0].seq, Seq::from_u64(maximum));
                assert_eq!(
                    events[0].origin,
                    Some(pos_core::EventOriginV1 {
                        origin_timeline_id: root,
                        origin_logical_seq: Seq::from_u64(maximum),
                    })
                );
            }
            assert!(store.conn.is_autocommit());
        }
        Ok(())
    }

    #[test]
    fn complete_event_reads_refuse_malformed_native_rows_without_partial_output() -> Fallible<()> {
        for sql in [
            "DELETE FROM events",
            "UPDATE events SET seq=2; UPDATE timelines SET head_seq=3 WHERE parent_id IS NULL",
            "UPDATE events SET wall_time=1.5",
            "UPDATE events SET signature=x'00'",
            "UPDATE events SET signature=zeroblob(64)",
            "UPDATE events SET origin_logical_seq=2",
            "UPDATE events SET payload=CAST(x'ff' AS TEXT)",
        ] {
            let (store, root, _) = fixture()?;
            assert_eq!(complete_events(&store, root)??.len(), 1);
            // Retained corruption is injected only in this native fixture;
            // the port, budget, snapshot and real containment gate are unchanged.
            store.conn.execute_batch(sql)?;
            assert_eq!(
                complete_events(&store, root)?,
                Err(Error::Read(ReadError::CorruptAuthority)),
                "accepted corrupt native Event: {sql}",
            );
        }
        Ok(())
    }
}
