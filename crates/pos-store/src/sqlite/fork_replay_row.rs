//! Closed selected-row queries and their protected cursor/check lifecycle.

use rusqlite::{Connection, Row, Rows, Statement};

use crate::fork_replay::NativeReadContextV1;
use pos_core::ForkAdmissionErrorV1 as Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
pub(super) enum SelectedRowV1<'key> {
    HostProbe,
    HostBlob,
    ChildProbe(&'key str),
    ChildFields(&'key str),
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
        }
    }

    fn query<'statement>(self, statement: &'statement mut Statement<'_>) -> rusqlite::Result<Rows<'statement>> {
        match self {
            Self::HostProbe | Self::HostBlob => statement.query([]),
            Self::ChildProbe(key) | Self::ChildFields(key) => statement.query([key]),
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
                .and_then(|()| query.query(&mut statement).map_err(|_| Error::StorageIndeterminate))
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
