//! Closed selected-row queries and their protected cursor/check lifecycle.

use rusqlite::{Connection, Row, Rows, Statement};

use super::fork_replay_event::EventCursorV1;
use crate::fork_replay::NativeReadContextV1;
use pos_core::{ForkAdmissionErrorV1 as Error, Hash};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub(super) enum SelectedRowV1<'key> {
    HostProbe,
    HostBlob,
    RegistryProbe,
    RegistryBlob,
    ChildProbe(&'key str),
    ChildFields(&'key str),
    ChainProbe(&'key str),
    ChainFields(&'key str),
    OriginPrefix(&'key str),
    BindingProbe(Hash),
    BindingFields(Hash),
    EventProbe(&'key str, EventCursorV1),
    EventFields(&'key str, i64),
    ClassifiedEventProbe(&'key str, i64),
    EventOriginProbe(&'key str),
    EventOriginBlob(&'key str),
    InterventionProbe(&'key str),
    InterventionBlob(&'key str),
    SuffixProbe(&'key str, Option<i64>),
    SuffixFields(&'key str, i64),
}

impl SelectedRowV1<'_> {
    const fn sql(self) -> &'static str {
        match self {
            Self::HostProbe => "SELECT typeof(fah1_cbor) = 'blob', length(fah1_cbor),
                CASE WHEN typeof(last_authority_wall_time) = 'integer'
                    AND last_authority_wall_time >= 0 THEN 1 ELSE 0 END
                FROM fork_admission_authority WHERE singleton = 1",
            Self::HostBlob => "SELECT fah1_cbor
                FROM fork_admission_authority WHERE singleton = 1",
            Self::RegistryProbe => "SELECT probe.* FROM (SELECT 1) AS boundary LEFT JOIN (
                SELECT typeof(state_cbor) = 'blob', length(state_cbor)
                FROM key_registry WHERE singleton = 1) AS probe ON 1 = 1",
            Self::RegistryBlob => "SELECT state_cbor FROM key_registry WHERE singleton = 1",
            Self::ChildProbe(_) => "SELECT
                typeof(name) = 'null', typeof(name) = 'text', length(CAST(name AS BLOB)),
                typeof(parent_id) = 'null', typeof(parent_id) = 'text', length(CAST(parent_id AS BLOB)),
                typeof(fork_seq) IN ('null', 'integer')
                FROM timelines WHERE id = ?1",
            Self::ChildFields(_) => "SELECT name, parent_id, fork_seq FROM timelines WHERE id = ?1",
            Self::ChainProbe(_) => "SELECT
                typeof(parent_id) = 'null', typeof(parent_id) = 'text', length(CAST(parent_id AS BLOB)),
                typeof(fork_seq) IN ('null', 'integer'), typeof(head_seq) = 'integer'
                FROM timelines WHERE id = ?1",
            Self::ChainFields(_) => "SELECT parent_id, fork_seq, head_seq FROM timelines WHERE id = ?1",
            Self::OriginPrefix(_) => "SELECT fork_seq FROM timelines WHERE id = ?1",
            Self::BindingProbe(_) => "SELECT
                typeof(principal_digest) = 'blob', length(principal_digest),
                typeof(pob1_cbor) = 'blob', length(pob1_cbor)
                FROM fork_principal_owner_bindings WHERE operation_id = ?1",
            Self::BindingFields(_) => "SELECT principal_digest, pob1_cbor
                FROM fork_principal_owner_bindings WHERE operation_id = ?1",
            Self::EventProbe(_, cursor) => cursor.sql(),
            Self::ClassifiedEventProbe(_, _) => super::fork_replay_event::EXACT_EVENT,
            Self::EventOriginProbe(_) => "SELECT probe.* FROM (SELECT 1) AS boundary LEFT JOIN (
                SELECT typeof(eor1_cbor) = 'blob', length(eor1_cbor)
                FROM fork_event_origins WHERE event_id = ?1) AS probe ON 1 = 1",
            Self::EventOriginBlob(_) => "SELECT eor1_cbor FROM fork_event_origins WHERE event_id = ?1",
            Self::InterventionProbe(_) => "SELECT probe.* FROM (SELECT 1) AS boundary LEFT JOIN (
                SELECT typeof(fia1_cbor) = 'blob', length(fia1_cbor)
                FROM fork_intervention_admissions WHERE event_id = ?1) AS probe ON 1 = 1",
            Self::InterventionBlob(_) => "SELECT fia1_cbor FROM fork_intervention_admissions WHERE event_id = ?1",
            Self::SuffixProbe(_, None) => super::fork_replay_suffix::FIRST_SUFFIX,
            Self::SuffixProbe(_, Some(_)) => super::fork_replay_suffix::AFTER_SUFFIX,
            Self::SuffixFields(_, _) => super::fork_replay_suffix::SUFFIX_FIELDS,
            Self::EventFields(_, _) => super::fork_replay_event::EVENT_FIELDS,
        }
    }

    fn query<'statement>(
        self,
        statement: &'statement mut Statement<'_>,
    ) -> rusqlite::Result<Rows<'statement>> {
        match self {
            Self::HostProbe | Self::HostBlob | Self::RegistryProbe | Self::RegistryBlob => {
                statement.query([])
            }
            Self::ChildProbe(key)
            | Self::ChildFields(key)
            | Self::ChainProbe(key)
            | Self::ChainFields(key)
            | Self::OriginPrefix(key)
            | Self::EventOriginProbe(key)
            | Self::EventOriginBlob(key)
            | Self::InterventionProbe(key)
            | Self::InterventionBlob(key)
            | Self::SuffixProbe(key, None) => statement.query([key]),
            Self::BindingProbe(operation) | Self::BindingFields(operation) => {
                statement.query([operation.as_bytes().as_slice()])
            }
            Self::EventProbe(key, cursor) => cursor.query(statement, key),
            Self::EventFields(key, seq) | Self::ClassifiedEventProbe(key, seq) => {
                statement.query(rusqlite::params![key, seq])
            }
            Self::SuffixProbe(key, Some(seq)) | Self::SuffixFields(key, seq) => {
                statement.query(rusqlite::params![key, seq])
            }
        }
    }
}

pub(super) fn selected_field_with_context<'budget, 'clock, T>(
    conn: &Connection,
    query: SelectedRowV1<'_>,
    context: &mut NativeReadContextV1<'budget, 'clock>,
    read: impl FnOnce(&Row<'_>, &mut NativeReadContextV1<'budget, 'clock>) -> Result<T>,
) -> Result<Option<T>> {
    context
        .check()
        .map_err(|_| Error::CorruptAuthority)
        .and_then(|()| {
            // Reuse only the compiled SQL, never rows or validated evidence.
            // Every execution still binds its key and crosses the same native
            // cursor, field, accounting and original-clock checkpoints below.
            conn.prepare_cached(query.sql())
                .map_err(|_| Error::StorageIndeterminate)
        })
        .and_then(|mut statement| {
            context
                .check()
                .map_err(|_| Error::CorruptAuthority)
                .and_then(|()| {
                    query
                        .query(&mut statement)
                        .map_err(|_| Error::StorageIndeterminate)
                })
                .and_then(|mut rows| {
                    context
                        .row_available()
                        .map_err(|_| Error::CorruptAuthority)
                        .and_then(|()| rows.next().map_err(|_| Error::StorageIndeterminate))
                        .and_then(|row| match row {
                            None => context
                                .check()
                                .map(|()| None)
                                .map_err(|_| Error::CorruptAuthority),
                            Some(row) => context
                                .suffix_row()
                                .map_err(|_| Error::CorruptAuthority)
                                .and_then(|()| read(row, context))
                                .and_then(|value| {
                                    context
                                        .check()
                                        .map(|()| Some(value))
                                        .map_err(|_| Error::CorruptAuthority)
                                }),
                        })
                })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayAuthorityReadErrorV1, ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use rusqlite::functions::FunctionFlags;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    #[test]
    fn exhausted_rows_refuse_before_the_native_cursor_steps(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        let steps = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&steps);
        conn.create_scalar_function("cursor_probe", 0, FunctionFlags::SQLITE_UTF8, move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(0_i64)
        })?;
        // Isolate the cursor owner's VM boundary, not a real Timeline or
        // admitted authority. This non-deterministic SQL function runs only
        // when SQLite actually steps the selected view, not during prepare.
        conn.execute_batch(
            "CREATE VIEW timelines AS
             SELECT 'child' AS id, cursor_probe() AS fork_seq",
        )?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let started = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 64, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
        for expected in [Ok(Some(0_i64)), Err(Error::CorruptAuthority)] {
            assert_eq!(
                selected_field_with_context(
                    &conn,
                    SelectedRowV1::OriginPrefix("child"),
                    &mut NativeReadContextV1::protected(&mut budget),
                    |row, context| {
                        context.bytes(8).map_err(|_| Error::CorruptAuthority)?;
                        row.get(0).map_err(|_| Error::StorageIndeterminate)
                    },
                ),
                expected,
            );
            // First read proves the real VM probe executes. The exhausted
            // second read must refuse before a second VM evaluation, even
            // though the later actual-row debit would also return an error.
            assert_eq!(steps.load(Ordering::SeqCst), 1);
            assert_eq!(budget.remaining_native_bytes(), 56);
        }
        assert_eq!(
            budget.check_time(),
            Err(ForkReplayAuthorityReadErrorV1::BoundsExceeded)
        );
        Ok(())
    }
}
