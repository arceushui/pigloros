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
    ChildProbe(&'key str),
    ChildFields(&'key str),
    ChainProbe(&'key str),
    ChainFields(&'key str),
    BindingProbe(Hash),
    BindingFields(Hash),
    EventProbe(&'key str, EventCursorV1),
    EventFields(&'key str, i64),
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
            Self::BindingProbe(_) => "SELECT
                typeof(principal_digest) = 'blob', length(principal_digest),
                typeof(pob1_cbor) = 'blob', length(pob1_cbor)
                FROM fork_principal_owner_bindings WHERE operation_id = ?1",
            Self::BindingFields(_) => "SELECT principal_digest, pob1_cbor
                FROM fork_principal_owner_bindings WHERE operation_id = ?1",
            Self::EventProbe(_, cursor) => cursor.sql(),
            Self::EventFields(_, _) => "SELECT seq, event_id, entity_id, event_type, payload, wall_time,
                causation_id, correlation_id, schema_version, payload_hash, signature,
                signature_owner_id, signature_role, signature_epoch, origin_timeline_id, origin_logical_seq
                FROM events WHERE timeline_id = ?1 AND seq = ?2",
        }
    }

    fn query<'statement>(
        self,
        statement: &'statement mut Statement<'_>,
    ) -> rusqlite::Result<Rows<'statement>> {
        match self {
            Self::HostProbe | Self::HostBlob => statement.query([]),
            Self::ChildProbe(key)
            | Self::ChildFields(key)
            | Self::ChainProbe(key)
            | Self::ChainFields(key) => statement.query([key]),
            Self::BindingProbe(operation) | Self::BindingFields(operation) => {
                statement.query([operation.as_bytes().as_slice()])
            }
            Self::EventProbe(key, cursor) => cursor.query(statement, key),
            Self::EventFields(key, seq) => statement.query(rusqlite::params![key, seq]),
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
            conn.prepare(query.sql())
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
