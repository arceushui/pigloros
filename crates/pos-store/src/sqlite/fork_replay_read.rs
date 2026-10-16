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
        let (from, to, count) = complete_event_range(head, range, bounds, &mut context)?;
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
                    next = next
                        .checked_add(1)
                        .ok_or(Error::Read(ReadError::CorruptAuthority))?;
                }
                Ok(())
            })?;
        }
        context.step(|_| {
            if events.len() == count {
                Ok(())
            } else {
                corrupt()
            }
        })?;
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
                context.step(|_| {
                    if event.seq.as_u64() == next {
                        Ok(())
                    } else {
                        corrupt()
                    }
                })?;
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
