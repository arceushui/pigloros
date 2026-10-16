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
