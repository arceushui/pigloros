//! `SQLite` adapter for Gateway-managed revisions (#304).
//!
//! Three tables sit beside the Gateway mode binding: the stored revisions
//! with their content, the payload-free tombstones erasure leaves, and the
//! idempotency records. A commit is one `BEGIN IMMEDIATE` transaction under
//! `synchronous=FULL` that reads the idempotency record, the persisted mode
//! binding and the resource head, and writes the revision row with the
//! binding it was produced under and its idempotency record together.
//!
//! Erasure deletes the revision row in one such transaction under
//! `secure_delete`, so `SQLite` overwrites the freed content, inserts the
//! tombstone and rewrites the request digest of its idempotency record, which
//! is derived from the content, to a constant; the connection's earlier
//! `secure_delete` setting is restored afterwards. It then asks for a
//! truncating WAL checkpoint so no committed page image of the content stays
//! in the write-ahead log. Its completion
//! evidence and erasure-inventory registration belong to the subject erasure
//! workflow (#309).

use pos_core::{
    admit_gateway_revision_v1, gateway_revision_mode_v1, replay_gateway_revision_v1, EntityId,
    GatewayModeBindingRecordV1, GatewayModeProfileRefV1, GatewayRevisionCommitV1,
    GatewayRevisionDraftV1, GatewayRevisionErasurePermitV1, GatewayRevisionErrorV1,
    GatewayRevisionKeyV1, GatewayRevisionPortV1, GatewayRevisionRecordV1, GatewayRevisionStateV1,
    GatewayRevisionTombstoneV1, ERASED_GATEWAY_REVISION_REQUEST_DIGEST,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::num::NonZeroU64;

use super::{
    gateway_mode_binding::{read_binding, sql_integer, SqlEpochV1},
    SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};

const fn column(
    name: &'static str,
    kind: &'static str,
    not_null: bool,
    primary_key: bool,
) -> SqliteSchemaColumn {
    SqliteSchemaColumn {
        name,
        kind,
        not_null,
        primary_key,
    }
}

/// The three revision tables, created and validated exactly.
pub(super) const GATEWAY_REVISION_SCHEMA_TABLES: &[SqliteSchemaTable] = &[
    SqliteSchemaTable {
        name: "gateway_revisions",
        columns_query: "PRAGMA table_info(gateway_revisions)",
        columns: &[
            column("kind", "INTEGER", true, true),
            column("resource_id", "BLOB", true, true),
            column("revision", "INTEGER", true, true),
            column("subject", "BLOB", true, false),
            column("digest", "BLOB", true, false),
            column("principal_id", "BLOB", true, false),
            column("mode_profile_id", "TEXT", true, false),
            column("mode_profile_digest", "BLOB", true, false),
            column("binding_epoch", "INTEGER", true, false),
            column("content", "BLOB", true, false),
        ],
        constraints: &[
            "CHECK (kind IN (1, 2))",
            "CHECK (length(resource_id) = 16)",
            "CHECK (revision >= 1)",
            "CHECK (length(subject) = 16)",
            "CHECK (length(digest) = 32)",
            "CHECK (length(principal_id) = 16)",
            "CHECK (length(mode_profile_digest) = 32)",
            "CHECK (binding_epoch >= 1)",
            "CHECK (length(content) BETWEEN 1 AND 65536)",
        ],
    },
    SqliteSchemaTable {
        name: "gateway_revision_tombstones",
        columns_query: "PRAGMA table_info(gateway_revision_tombstones)",
        columns: &[
            column("kind", "INTEGER", true, true),
            column("resource_id", "BLOB", true, true),
            column("revision", "INTEGER", true, true),
            column("subject", "BLOB", true, false),
            column("digest", "BLOB", true, false),
        ],
        constraints: &[
            "CHECK (kind IN (1, 2))",
            "CHECK (length(resource_id) = 16)",
            "CHECK (revision >= 1)",
            "CHECK (length(subject) = 16)",
            "CHECK (length(digest) = 32)",
        ],
    },
    SqliteSchemaTable {
        name: "gateway_revision_requests",
        columns_query: "PRAGMA table_info(gateway_revision_requests)",
        columns: &[
            column("principal_id", "BLOB", true, true),
            column("kind", "INTEGER", true, true),
            column("key_digest", "BLOB", true, true),
            column("resource_id", "BLOB", true, false),
            column("revision", "INTEGER", true, false),
            column("request_digest", "BLOB", true, false),
        ],
        constraints: &[
            "CHECK (length(principal_id) = 16)",
            "CHECK (kind IN (1, 2))",
            "CHECK (length(key_digest) = 32)",
            "CHECK (length(resource_id) = 16)",
            "CHECK (revision >= 1)",
            "CHECK (length(request_digest) = 32)",
        ],
    },
];

/// One step inside a revision transaction: an adapter failure, or the
/// port's own answer.
type RevisionStep<T> = rusqlite::Result<Result<T, GatewayRevisionErrorV1>>;

/// The raw columns of one stored revision: subject, digest, Principal, mode
/// profile ID and digest, binding epoch and content.
type RevisionRowV1 = (
    [u8; 16],
    [u8; 32],
    [u8; 16],
    String,
    [u8; 32],
    SqlEpochV1,
    Vec<u8>,
);

/// The raw columns of one idempotency record: resource, revision and
/// request digest.
type RequestRowV1 = ([u8; 16], SqlEpochV1, [u8; 32]);

/// Collapse an adapter failure into the port's closed unavailable error.
fn settle<T>(step: RevisionStep<T>) -> Result<T, GatewayRevisionErrorV1> {
    step.map_err(|_| GatewayRevisionErrorV1::Unavailable)
        .and_then(std::convert::identity)
}

const fn subject_of(bytes: [u8; 16]) -> EntityId {
    EntityId::from_ulid(ulid::Ulid::from_bytes(bytes))
}

const fn tombstone_of(
    key: GatewayRevisionKeyV1,
    subject: [u8; 16],
    digest: [u8; 32],
) -> GatewayRevisionTombstoneV1 {
    GatewayRevisionTombstoneV1::new(key, subject_of(subject), digest)
}

/// The stored revision of one decoded row; a mode profile reference that
/// is not canonical is an invalid record.
fn present_state(
    key: GatewayRevisionKeyV1,
    row: RevisionRowV1,
) -> Result<GatewayRevisionStateV1, GatewayRevisionErrorV1> {
    let (subject, digest, principal_id, profile_id, profile_digest, epoch, content) = row;
    GatewayModeProfileRefV1::try_new(&profile_id, profile_digest)
        .ok()
        .map(|profile| {
            GatewayRevisionStateV1::Present(GatewayRevisionRecordV1::new(
                tombstone_of(key, subject, digest),
                principal_id,
                GatewayModeBindingRecordV1::new(profile, epoch.0),
                content,
            ))
        })
        .ok_or(GatewayRevisionErrorV1::InvalidRecord)
}

fn key_params(key: GatewayRevisionKeyV1) -> (u8, [u8; 16], i64) {
    (
        key.kind().code(),
        key.resource_id(),
        sql_integer(key.revision().get()),
    )
}

fn read_tombstone(
    conn: &Connection,
    key: GatewayRevisionKeyV1,
) -> rusqlite::Result<Option<GatewayRevisionStateV1>> {
    let (kind, resource_id, revision) = key_params(key);
    conn.query_row(
        "SELECT subject, digest FROM gateway_revision_tombstones
         WHERE kind = ?1 AND resource_id = ?2 AND revision = ?3",
        params![kind, resource_id, revision],
        |row| <([u8; 16], [u8; 32])>::try_from(row),
    )
    .optional()
    .map(|row| {
        row.map(|(subject, digest)| {
            GatewayRevisionStateV1::Erased(tombstone_of(key, subject, digest))
        })
    })
}

/// The state of revision `key`: its stored row, else its tombstone.
fn read_state(
    conn: &Connection,
    key: GatewayRevisionKeyV1,
) -> RevisionStep<Option<GatewayRevisionStateV1>> {
    let (kind, resource_id, revision) = key_params(key);
    conn.query_row(
        "SELECT subject, digest, principal_id, mode_profile_id, mode_profile_digest,
                binding_epoch, content
         FROM gateway_revisions WHERE kind = ?1 AND resource_id = ?2 AND revision = ?3",
        params![kind, resource_id, revision],
        |row| <RevisionRowV1>::try_from(row),
    )
    .optional()
    .and_then(|row| match row {
        Some(row) => Ok(present_state(key, row).map(Some)),
        None => read_tombstone(conn, key).map(Ok),
    })
}

/// The highest revision of the draft's resource, stored or erased.
fn read_head(
    conn: &Connection,
    draft: &GatewayRevisionDraftV1,
) -> rusqlite::Result<Option<NonZeroU64>> {
    conn.query_row(
        "SELECT MAX(revision) FROM (
             SELECT revision FROM gateway_revisions WHERE kind = ?1 AND resource_id = ?2
             UNION ALL
             SELECT revision FROM gateway_revision_tombstones
             WHERE kind = ?1 AND resource_id = ?2
         )",
        params![draft.idempotency().kind().code(), draft.resource_id()],
        |row| row.get::<_, Option<SqlEpochV1>>(0),
    )
    .map(|head| head.map(|head| head.0))
}

fn read_request(
    conn: &Connection,
    draft: &GatewayRevisionDraftV1,
) -> rusqlite::Result<Option<RequestRowV1>> {
    let request = draft.idempotency();
    conn.query_row(
        "SELECT resource_id, revision, request_digest FROM gateway_revision_requests
         WHERE principal_id = ?1 AND kind = ?2 AND key_digest = ?3",
        params![
            request.principal_id(),
            request.kind().code(),
            request.key_digest()
        ],
        |row| <RequestRowV1>::try_from(row),
    )
    .optional()
}

/// The answer to a retry of a stored request.
fn replay(
    conn: &Connection,
    stored: RequestRowV1,
    draft: &GatewayRevisionDraftV1,
) -> RevisionStep<GatewayRevisionCommitV1> {
    let (resource_id, revision, request_digest) = stored;
    let key = GatewayRevisionKeyV1::new(draft.idempotency().kind(), resource_id, revision.0);
    read_state(conn, key).map(|state| {
        state.and_then(|state| replay_gateway_revision_v1(state, request_digest, draft))
    })
}

fn insert_record(
    conn: &Connection,
    draft: &GatewayRevisionDraftV1,
    record: &GatewayRevisionRecordV1,
) -> rusqlite::Result<()> {
    let tombstone = record.tombstone();
    let (kind, resource_id, revision) = key_params(tombstone.key());
    let mode = record.mode();
    conn.execute(
        "INSERT INTO gateway_revisions
         (kind, resource_id, revision, subject, digest, principal_id, mode_profile_id,
          mode_profile_digest, binding_epoch, content)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            kind,
            resource_id,
            revision,
            tombstone.subject().inner().to_bytes(),
            tombstone.digest(),
            record.principal_id(),
            mode.profile().profile_id(),
            mode.profile().profile_digest(),
            sql_integer(mode.binding_epoch().get()),
            record.content()
        ],
    )
    .and_then(|_| {
        let request = draft.idempotency();
        conn.execute(
            "INSERT INTO gateway_revision_requests
             (principal_id, kind, key_digest, resource_id, revision, request_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.principal_id(),
                kind,
                request.key_digest(),
                resource_id,
                revision,
                request.request_digest()
            ],
        )
    })
    .map(drop)
}

/// Admit a fresh request under the persisted binding and record it.
fn admit(
    conn: &Connection,
    attached: Option<NonZeroU64>,
    draft: &GatewayRevisionDraftV1,
) -> RevisionStep<GatewayRevisionCommitV1> {
    let binding = read_binding(conn).map(|binding| binding.ok().flatten());
    binding.and_then(
        |binding| match gateway_revision_mode_v1(binding, attached) {
            Ok(mode) => {
                let parent = draft
                    .parent_key()
                    .map_or(Ok(Ok(None)), |key| read_state(conn, key));
                parent.and_then(|parent| {
                    read_head(conn, draft).and_then(|head| {
                        match parent.and_then(|parent| {
                            admit_gateway_revision_v1(draft, parent.as_ref(), head)
                        }) {
                            Ok(()) => {
                                let record = draft.to_record(mode);
                                insert_record(conn, draft, &record)
                                    .map(|()| Ok(GatewayRevisionCommitV1::Committed(record)))
                            }
                            Err(error) => Ok(Err(error)),
                        }
                    })
                })
            }
            Err(error) => Ok(Err(error)),
        },
    )
}

fn commit_in_transaction(
    conn: &Connection,
    attached: Option<NonZeroU64>,
    draft: &GatewayRevisionDraftV1,
) -> RevisionStep<GatewayRevisionCommitV1> {
    read_request(conn, draft).and_then(|stored| match stored {
        Some(stored) => replay(conn, stored, draft),
        None => admit(conn, attached, draft),
    })
}

fn erase_in_transaction(
    conn: &Connection,
    key: GatewayRevisionKeyV1,
) -> RevisionStep<Option<GatewayRevisionTombstoneV1>> {
    read_state(conn, key).and_then(|state| match state {
        Ok(Some(GatewayRevisionStateV1::Present(record))) => {
            let tombstone = *record.tombstone();
            let (kind, resource_id, revision) = key_params(key);
            conn.execute(
                "DELETE FROM gateway_revisions
                 WHERE kind = ?1 AND resource_id = ?2 AND revision = ?3",
                params![kind, resource_id, revision],
            )
            .and_then(|_| {
                conn.execute(
                    "INSERT INTO gateway_revision_tombstones
                     (kind, resource_id, revision, subject, digest)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        kind,
                        resource_id,
                        revision,
                        tombstone.subject().inner().to_bytes(),
                        tombstone.digest()
                    ],
                )
            })
            .and_then(|_| {
                conn.execute(
                    "UPDATE gateway_revision_requests SET request_digest = ?4
                     WHERE kind = ?1 AND resource_id = ?2 AND revision = ?3",
                    params![
                        kind,
                        resource_id,
                        revision,
                        ERASED_GATEWAY_REVISION_REQUEST_DIGEST
                    ],
                )
            })
            .map(|_| Ok(Some(tombstone)))
        }
        other => Ok(other.map(|state| state.map(|state| *state.tombstone()))),
    })
}

/// Commit a successful step, roll back any other.
///
/// A `COMMIT` that fails, for example on a deferred constraint, leaves the
/// transaction open, so it is rolled back before the failure is returned.
fn finish<T>(conn: &Connection, step: RevisionStep<T>) -> RevisionStep<T> {
    let commit = step.as_ref().is_ok_and(Result::is_ok);
    conn.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })
        .inspect_err(|_| drop(conn.execute_batch("ROLLBACK")))
        .and(step)
}

/// Run one revision change as a `BEGIN IMMEDIATE` transaction under
/// `synchronous=FULL` (after `prelude`), then restore the store's
/// `synchronous=NORMAL`.
fn revision_transaction<T>(
    conn: &Connection,
    prelude: &str,
    body: impl FnOnce(&Connection) -> RevisionStep<T>,
) -> Result<T, GatewayRevisionErrorV1> {
    let step = conn
        .execute_batch(prelude)
        .and_then(|()| conn.execute_batch("PRAGMA synchronous=FULL; BEGIN IMMEDIATE"))
        .and_then(|()| finish(conn, body(conn)));
    drop(conn.execute_batch("PRAGMA synchronous=NORMAL"));
    settle(step)
}

impl SqliteStore {
    pub(super) fn validate_gateway_revision_schema(
        &self,
    ) -> Result<(), pos_core::error::CoreError> {
        GATEWAY_REVISION_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
    }
}

impl GatewayRevisionPortV1 for SqliteStore {
    fn commit_gateway_revision(
        &mut self,
        draft: GatewayRevisionDraftV1,
    ) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1> {
        let attached = self.mode_binding_epoch;
        revision_transaction(&self.conn, "", |conn| {
            commit_in_transaction(conn, attached, &draft)
        })
    }

    fn load_gateway_revision(
        &self,
        key: GatewayRevisionKeyV1,
    ) -> Result<Option<GatewayRevisionStateV1>, GatewayRevisionErrorV1> {
        settle(read_state(&self.conn, key))
    }

    fn erase_gateway_revision(
        &mut self,
        permit: GatewayRevisionErasurePermitV1,
    ) -> Result<Option<GatewayRevisionTombstoneV1>, GatewayRevisionErrorV1> {
        let previous = self
            .conn
            .query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0);
        let erased = revision_transaction(&self.conn, "PRAGMA secure_delete=ON", |conn| {
            erase_in_transaction(conn, permit.key())
        });
        drop(
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())),
        );
        drop(
            self.conn
                .execute_batch(&format!("PRAGMA secure_delete={previous}")),
        );
        erased
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{GatewayRevisionErasureHostV1, GatewayRevisionKindV1};

    #[test]
    fn erasure_restores_the_connection_secure_delete_setting() {
        let mut store = SqliteStore::open_in_memory()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        let setting = |store: &SqliteStore| {
            store
                .conn
                .query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))
                .unwrap_or(-1)
        };
        let before = setting(&store);
        let key =
            GatewayRevisionKeyV1::new(GatewayRevisionKindV1::Preference, [1; 16], NonZeroU64::MIN);
        assert_eq!(
            store
                .erase_gateway_revision(GatewayRevisionErasureHostV1::new().authorize_erasure(key)),
            Ok(None)
        );
        assert_eq!(setting(&store), before);
    }
}
