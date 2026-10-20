//! The selected `IKR1`/`IKT1` probe and fetch on one held imported snapshot.

use crate::{
    fork_event_authority::ValidatedImportV1,
    fork_manifest_publication::{PublicationSourceErrorV1, PublicationSourceResultV1},
    fork_replay::NativeReadContextV1,
};
use rusqlite::{params, Connection, Row};

/// Both exact import keys select the retained evidence (ADR-105 erratum E12).
const RETAINED_KEY_SQL: &str = "SELECT evidence.ikr1_cbor, evidence.ikt1_cbor
    FROM imported_fork_key_evidence AS evidence
    JOIN imported_fork_attribution_admissions AS admission
      ON admission.import_operation_id = evidence.import_operation_id
    WHERE evidence.import_operation_id = ?1 AND admission.full_envelope_digest = ?2";

const RETAINED_KEY_PROBE_SQL: &str = "SELECT
    typeof(evidence.ikr1_cbor) = 'blob', length(evidence.ikr1_cbor),
    evidence.ikt1_cbor IS NULL OR typeof(evidence.ikt1_cbor) = 'blob', length(evidence.ikt1_cbor)
    FROM imported_fork_key_evidence AS evidence
    JOIN imported_fork_attribution_admissions AS admission
      ON admission.import_operation_id = evidence.import_operation_id
    WHERE evidence.import_operation_id = ?1 AND admission.full_envelope_digest = ?2";

pub(super) struct StoredRetainedKeyV1 {
    pub(super) record: Vec<u8>,
    pub(super) tombstone: Option<Vec<u8>>,
}

struct RetainedKeyLengthsV1 {
    record: usize,
    tombstone: Option<usize>,
}

/// Unlike other selected-row readers, check after stepping before testing
/// required-row absence or charging the actual row. Retain both native scopes
/// through the callback, and keep probe/fetch scopes separate.
fn with_selected_key_row<'budget, 'clock, T>(
    conn: &Connection,
    sql: &str,
    import: ValidatedImportV1,
    context: &mut NativeReadContextV1<'budget, 'clock>,
    read: impl FnOnce(
        &Row<'_>,
        &mut NativeReadContextV1<'budget, 'clock>,
    ) -> PublicationSourceResultV1<T>,
) -> PublicationSourceResultV1<T> {
    use PublicationSourceErrorV1::{Invalid, Storage};
    context
        .check()
        .map_err(|_| Invalid)
        .and_then(|()| conn.prepare(sql).map_err(|_| Storage))
        .and_then(|mut statement| {
            context
                .check()
                .map_err(|_| Invalid)
                .and_then(|()| {
                    statement
                        .query(params![
                            import.import_operation_id.as_bytes().as_slice(),
                            import.full_envelope_digest.as_bytes().as_slice(),
                        ])
                        .map_err(|_| Storage)
                })
                .and_then(|mut rows| {
                    context
                        .row_available()
                        .map_err(|_| Invalid)
                        .and_then(|()| rows.next().map_err(|_| Storage))
                        .and_then(|row| {
                            context
                                .check()
                                .map_err(|_| Invalid)
                                .and_then(|()| row.ok_or(Invalid))
                        })
                        .and_then(|row| {
                            context
                                .suffix_row()
                                .map_err(|_| Invalid)
                                .and_then(|()| read(row, context))
                        })
                })
        })
}

fn retained_key_lengths_with_context(
    conn: &Connection,
    import: ValidatedImportV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> PublicationSourceResultV1<RetainedKeyLengthsV1> {
    use PublicationSourceErrorV1::{Invalid, Storage};
    with_selected_key_row(
        conn,
        RETAINED_KEY_PROBE_SQL,
        import,
        context,
        |row, context| {
            row.get::<_, bool>(0)
            .map_err(|_| Storage)
            .and_then(|record_is_blob| {
                row.get::<_, bool>(2)
                    .map_err(|_| Storage)
                    .and_then(|tombstone_is_blob_or_null| {
                        if !record_is_blob || !tombstone_is_blob_or_null {
                            return Err(Storage);
                        }
                        row.get::<_, i64>(1)
                            .map_err(|_| Storage)
                            .and_then(|length| usize::try_from(length).map_err(|_| Invalid))
                            .and_then(|record| {
                                row.get::<_, Option<i64>>(3)
                                    .map_err(|_| Storage)
                                    .and_then(|length| {
                                        length
                                            .map(usize::try_from)
                                            .transpose()
                                            .map_err(|_| Invalid)
                                    })
                                    .and_then(|tombstone| {
                                        if record > pos_core::MAX_IMPORTED_KEY_RECORD_BYTES_V1
                                            || tombstone.is_some_and(|length| {
                                                length > pos_core::MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1
                                            })
                                        {
                                            return Err(Invalid);
                                        }
                                        context
                                            .check()
                                            .map(|()| RetainedKeyLengthsV1 { record, tombstone })
                                            .map_err(|_| Invalid)
                                    })
                            })
                    })
            })
        },
    )
}

/// Type and size gates precede both raw getters on the same held snapshot.
pub(super) fn retained_key_bytes_with_context(
    conn: &Connection,
    import: ValidatedImportV1,
    context: &mut NativeReadContextV1<'_, '_>,
) -> PublicationSourceResultV1<StoredRetainedKeyV1> {
    use PublicationSourceErrorV1::{Invalid, Storage};
    retained_key_lengths_with_context(conn, import, context).and_then(|lengths| {
        with_selected_key_row(conn, RETAINED_KEY_SQL, import, context, |row, context| {
            context
                .bytes(lengths.record)
                .map_err(|_| Invalid)
                .and_then(|()| row.get::<_, Vec<u8>>(0).map_err(|_| Storage))
                .and_then(|record| {
                    context
                        .check()
                        .map_err(|_| Invalid)
                        .and_then(|()| {
                            lengths
                                .tombstone
                                .map_or(Ok(()), |length| context.bytes(length).map_err(|_| Invalid))
                        })
                        .and_then(|()| row.get::<_, Option<Vec<u8>>>(1).map_err(|_| Storage))
                        .and_then(|tombstone| {
                            context
                                .check()
                                .map(|()| StoredRetainedKeyV1 { record, tombstone })
                                .map_err(|_| Invalid)
                        })
                })
        })
    })
}
