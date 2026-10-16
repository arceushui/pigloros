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

    fn lineage_freshness(&self, context: &mut LineageReadContextV1<'_, '_>) -> ReadResult<()> {
        context.step(|context| {
            if !self.erasure_gate_bound {
                return Ok(());
            }
            let observed = self
                .lineage_row("PRAGMA data_version", [], context, |row, context| {
                    integer(row, 0, context)
                })
                .map_err(|error| match error {
                    Error::Read(ReadError::BoundsExceeded) => error,
                    _ => Error::ContainmentUnavailable,
                })?;
            if observed != Some(self.erasure_inventory_data_version) {
                return Err(Error::ContainmentUnavailable);
            }
            let gate = self
                .erasure_gate
                .as_deref()
                .ok_or(Error::ContainmentUnavailable)?;
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
            self.lineage_freshness(context)?;
            let mut result = Err(Error::ContainmentUnavailable);
            let fenced = gate.with_fence(timeline, ErasureProtectedOperationV1::Read, &mut || {
                result = effect(context);
            });
            // A latched refusal stops semantic work. Otherwise completion F
            // still executes after a native None/error or a gate denial.
            context.check()?;
            self.lineage_freshness(context)?;
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
}
