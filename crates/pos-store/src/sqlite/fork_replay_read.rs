//! Complete ADR-118 Event reads on the already-held native interval.

use super::{
    fork_replay_event::{EventRowLengthsV1, EventRowReaderV1, EVENT_FIELDS, REPLAY_EVENTS_PROBE},
    SqliteStore,
};
use crate::{
    fork_replay::{
        complete_event_range, corrupt, history_head, history_segment, read_visible_history,
        LineageReadContextV1, LineageReadResult, ReplayEventStagingV1,
    },
    ForkReplayAuthorityReadErrorV1 as ReadError, ForkReplayLineageReadErrorV1 as Error,
    ForkReplayReadBudgetV1,
};
use pos_core::{Event, EventReadBounds, ForkAdmissionErrorV1, Seq, SeqRange, TimelineId};
use rusqlite::params;

fn probe_error(error: ForkAdmissionErrorV1) -> Error {
    Error::Read(if error == ForkAdmissionErrorV1::StorageIndeterminate {
        ReadError::StorageUnavailable
    } else {
        ReadError::CorruptAuthority
    })
}

impl SqliteStore {
    pub(super) fn read_replay_events(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> LineageReadResult<Vec<Event>> {
        let mut context = LineageReadContextV1::for_events(budget, bounds)?;
        self.require_fork_replay_interval(&mut context)?;
        let history =
            read_visible_history(timeline_id, &mut context, |member, visited, context| {
                self.read_lineage_member(member, visited, context)
            })?;
        let head = history_head(&history, &mut context)?;
        let (from, to) = complete_event_range(head, range, bounds, &mut context)?;
        let mut events = ReplayEventStagingV1::default();
        let mut total_bytes = 0_usize;
        for (index, (node, _)) in history.iter().enumerate() {
            let (prefix, length) = history_segment(&history, index, &mut context)?;
            if length == 0 {
                continue;
            }
            let first = from.max(prefix + 1);
            let last = to.min(prefix + length);
            if first > last {
                continue;
            }
            let timeline = node.timeline_id();
            self.with_replay_read_fence(*timeline, &mut context, |context| {
                context.bytes(26)?;
                let key = timeline.to_string();
                let mut next = first - prefix;
                let end = last - prefix;
                while next <= end {
                    let (lengths, next_total) =
                        self.probe_replay_event(&key, (next, end), bounds, total_bytes, context)?;
                    self.read_replay_event(
                        &key,
                        &lengths,
                        (timeline, prefix, next),
                        &mut events,
                        context,
                    )?;
                    total_bytes = next_total;
                    // end <= length <= the native nonnegative i64 head:
                    // advancing once beyond that endpoint still fits in u64.
                    next += 1;
                }
                Ok(())
            })?;
        }
        // Every selected coordinate must pass the exact-next probe and exact
        // key fetch before one push. A gap or early EOF already returns an
        // error, and the held snapshot/sealed fence preserve that cardinality.
        Ok(events.into_events())
    }

    /// ER0 owns only fixed descriptors and the already-funded next cursor.
    fn probe_replay_event(
        &self,
        key: &str,
        (next, end): (u64, u64),
        bounds: EventReadBounds,
        total_bytes: usize,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> LineageReadResult<(EventRowLengthsV1, usize)> {
        self.lineage_row(
            REPLAY_EVENTS_PROBE,
            params![
                key,
                super::seq_as_i64(Seq::from_u64(next)),
                super::seq_as_i64(Seq::from_u64(end))
            ],
            context,
            |row, context| {
                let lengths = EventRowLengthsV1::probe(row, &mut context.native())
                    .map_err(probe_error)?
                    .ok_or(Error::Read(ReadError::CorruptAuthority))?;
                if lengths.seq <= 0 || u64::try_from(lengths.seq).ok() != Some(next) {
                    return corrupt();
                }
                let payload = lengths.columns[4];
                let kind = lengths.columns[3];
                let next_total = payload
                    .checked_add(kind)
                    .and_then(|bytes| total_bytes.checked_add(bytes));
                context.require(
                    payload <= bounds.max_payload_bytes()
                        && kind <= bounds.max_event_type_bytes()
                        && next_total.is_some_and(|total| total <= bounds.max_total_bytes()),
                )?;
                context.bytes(8)?;
                context
                    .native()
                    .require_bytes(lengths.total())
                    .map_err(|_| Error::Read(ReadError::BoundsExceeded))?;
                Ok((lengths, next_total.unwrap_or(usize::MAX)))
            },
        )?
        .ok_or(Error::Read(ReadError::CorruptAuthority))
    }

    /// ER1 moves its funded native buffers into the operation's scrub owner.
    fn read_replay_event(
        &self,
        key: &str,
        lengths: &EventRowLengthsV1,
        (timeline, prefix, next): (&TimelineId, u64, u64),
        events: &mut ReplayEventStagingV1,
        context: &mut LineageReadContextV1<'_, '_>,
    ) -> LineageReadResult<()> {
        self.lineage_row(
            EVENT_FIELDS,
            params![key, lengths.seq],
            context,
            |row, context| {
                let decoded = super::decode_event_row_with_reader(&mut EventRowReaderV1::new(
                    row,
                    &mut context.native(),
                    Some(lengths),
                ));
                // Take scrub ownership before any post-decode clock,
                // comparison or origin check can fail.
                let event =
                    events.push(decoded.map_err(|_| Error::Read(ReadError::CorruptAuthority))?);
                // ER0 required lengths.seq == next. ER1 selects that exact
                // primary key in the same snapshot and decodes its seq column.
                context.step(|_| {
                    crate::finalize_committed_origins(
                        *timeline,
                        prefix,
                        std::slice::from_mut(event),
                    )
                    .map_err(|_| Error::Read(ReadError::CorruptAuthority))
                })?;
                event.seq = Seq::from_u64(prefix + next);
                Ok(())
            },
        )?
        .ok_or(Error::Read(ReadError::CorruptAuthority))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::ForkReplayReadLimitsV1;
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        CanonicalBytes, EntityId, ErasureContainmentGateV1, ErasureInventoryPersistencePortV1,
        ErasureProtectedEffectDispositionV1, EventDraft, EventStore, Kind,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
    type ReadTranscript = Arc<Mutex<Vec<(String, String, bool)>>>;

    fn redact_projected_sequence(conn: &rusqlite::Connection) -> Fallible<ReadTranscript> {
        let transcript = Arc::new(Mutex::new(Vec::new()));
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
                let ignored = reads.is_empty();
                reads.push((table_name.to_owned(), column_name.to_owned(), ignored));
                if ignored {
                    return Authorization::Ignore;
                }
            }
            Authorization::Allow
        }))?;
        Ok(transcript)
    }

    fn assert_projected_sequence_only(transcript: &ReadTranscript) -> Fallible<()> {
        let reads = transcript.lock().map_err(|_| "read observer poisoned")?;
        let actual: Vec<_> = reads
            .iter()
            .map(|(table, column, ignored)| (table.as_str(), column.as_str(), *ignored))
            .collect();
        let columns = [
            "seq",
            "seq",
            "wall_time",
            "schema_version",
            "signature_role",
            "signature_epoch",
            "origin_logical_seq",
            "event_id",
            "event_id",
            "entity_id",
            "entity_id",
            "event_type",
            "event_type",
            "payload",
            "payload",
            "causation_id",
            "causation_id",
            "correlation_id",
            "correlation_id",
            "payload_hash",
            "payload_hash",
            "signature",
            "signature",
            "signature_owner_id",
            "signature_owner_id",
            "origin_timeline_id",
            "origin_timeline_id",
            "timeline_id",
            "seq",
            "seq",
            "seq",
        ];
        let expected: Vec<_> = columns
            .into_iter()
            .enumerate()
            .map(|(index, column)| ("events", column, index == 0))
            .collect();
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn projected_sequence_redaction_preserves_the_real_row_and_funded_event_retry() -> Fallible<()>
    {
        for held_snapshot in [false, true] {
            let mut store = SqliteStore::open(":memory:")?;
            store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
            let timeline = store.create_timeline("native Event probe")?.id();
            drop(store.append(
                timeline,
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("ordinary"),
                    CanonicalBytes::from_static(&[0xf6]),
                )],
            )?);
            let expected = store.read(timeline, SeqRange::all())?;
            let key = timeline.to_string();
            let interval = if held_snapshot {
                Some(store.begin_protected_effect_interval()?)
            } else {
                None
            };
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            // Failed probe1 + healthy probe1/raw1. Healthy bytes: descriptor8,
            // three ULIDs78, kind8, payload1 and payload hash32 =127.
            let limits = ForkReplayReadLimitsV1::new(1, 1, 3, 127, 30_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let bounds =
                EventReadBounds::new_with_total_bytes_and_elapsed(1, 8, 1, 1, 9, 30_000_000);
            let observed = redact_projected_sequence(&store.conn)?;
            let failed = store.probe_replay_event(
                &key,
                (1, 1),
                bounds,
                0,
                &mut LineageReadContextV1::for_events(&mut budget, bounds)?,
            );
            store
                .conn
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
            assert_projected_sequence_only(&observed)?;
            assert_eq!(failed.err(), Some(Error::Read(ReadError::CorruptAuthority)));
            assert_eq!(budget.remaining_native_bytes(), 127);
            budget.check_time()?;
            let (lengths, total) = store.probe_replay_event(
                &key,
                (1, 1),
                bounds,
                0,
                &mut LineageReadContextV1::for_events(&mut budget, bounds)?,
            )?;
            assert_eq!(lengths.seq, 1);
            assert_eq!(
                lengths.columns,
                [0, 26, 26, 8, 1, 0, 0, 0, 0, 32, 0, 0, 0, 0, 26, 0]
            );
            assert_eq!(total, 9);
            assert_eq!(budget.remaining_native_bytes(), 119);
            let mut events = ReplayEventStagingV1::default();
            store.read_replay_event(
                &key,
                &lengths,
                (&timeline, 0, 1),
                &mut events,
                &mut LineageReadContextV1::for_events(&mut budget, bounds)?,
            )?;
            assert_eq!(events.into_events(), expected);
            assert_eq!(budget.remaining_native_bytes(), 0);
            budget.check_time()?;
            assert!(budget.charge_rows(1).is_err());
            assert!(budget.check_time().is_err());
            if let Some(interval) = interval {
                store.finish_protected_effect_interval(
                    interval,
                    ErasureProtectedEffectDispositionV1::Rollback,
                )?;
            }
            assert!(store.conn.is_autocommit());
        }
        Ok(())
    }
}
