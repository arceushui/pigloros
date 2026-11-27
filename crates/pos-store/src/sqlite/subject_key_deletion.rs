#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-137 D1-D4 durable subject-key deletion receipts and finalization.
//!
//! Key destruction for a `SubjectDataEncryption` identity runs in the owner
//! process in ADR-097 section 5 order. This module owns the shared-store half
//! of that flow:
//!
//! - the `subject_key_deletion_receipts` table (D1), one row per destroyed
//!   artifact (wrap file, binding file or SNL1 row) or per absent-at-start
//!   kind, written `Started` before any unlink and `Confirmed` after the
//!   #206 durable deletion;
//! - the receipt digests that bind a row to its request (D1);
//! - [`SqliteStore::complete_subject_key_destruction_with_receipts`], which
//!   finalizes the registry tombstone and checks every receipt in one
//!   `BEGIN IMMEDIATE` (D2 step 6).
//!
//! The file inventory, the unlink, the SNL1 ledger replacement and the D3/D4
//! recovery decisions belong to the owner process, which calls these methods.
//! Only the owner process writes the table; the Gateway composition has no
//! API that does, and may only read it as evidence. Everything here stays
//! test-support gated until owner activation (#1438).
//!
//! Only a writable open creates and validates the table, so a read-only open
//! never creates it. Ungating in #1438 must remove both `cfg` gates together,
//! this module's and the writable-open call in `sqlite.rs`.

use pos_core::{
    deletion_receipt, error::CoreError, EventStore, Hash, KeyDestructionOutcomeV1,
    KeyDestructionRequestV1, KeyRegistryStateV1, KeyRoleV1,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_immediate_scope, sqlite_schema_ddl, SqliteImmediateScopeV1,
    SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};

/// The D1 table, keyed by `(request_digest, artifact, artifact_identity)`.
///
/// The builder creates a non-`STRICT` table, so the `typeof` checks give the
/// same column typing that `STRICT` would. The two row-state checks pin the
/// `Started` and `Confirmed` shapes: a `Started` row has no receipt digest, a
/// `Confirmed` row has one.
const SUBJECT_KEY_DELETION_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "subject_key_deletion_receipts",
    columns_query: "PRAGMA table_info(subject_key_deletion_receipts)",
    columns: &[
        SqliteSchemaColumn {
            name: "request_digest",
            kind: "BLOB",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "owner_id",
            kind: "TEXT",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "epoch",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "artifact",
            kind: "INTEGER",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "artifact_identity",
            kind: "BLOB",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "state",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "receipt_digest",
            kind: "BLOB",
            not_null: false,
            primary_key: false,
        },
    ],
    constraints: &[
        "CHECK (typeof(request_digest) = 'blob')",
        "CHECK (length(request_digest) = 32)",
        "CHECK (typeof(owner_id) = 'text')",
        "CHECK (typeof(epoch) = 'integer')",
        "CHECK (epoch >= 1)",
        "CHECK (typeof(artifact) = 'integer')",
        "CHECK (artifact IN (1, 2, 3))",
        "CHECK (typeof(artifact_identity) = 'blob')",
        "CHECK (length(artifact_identity) <= 64)",
        "CHECK (typeof(state) = 'integer')",
        "CHECK (state IN (1, 2))",
        "CHECK (receipt_digest IS NULL OR (typeof(receipt_digest) = 'blob' AND length(receipt_digest) = 32))",
        "CHECK ((state = 1 AND receipt_digest IS NULL) OR (state = 2 AND receipt_digest IS NOT NULL))",
    ],
}];

/// Reads the rows of one request, one past the largest legitimate count.
///
/// The inventory is bounded at 4,096 directory entries, each of which yields
/// at most one row; the SNL1 row and one absent-at-start row for the other
/// file kind add two more, so [`MAX_RECEIPT_ROWS`] is 4,098.
const REQUEST_ROWS_SQL: &str = "SELECT artifact, artifact_identity, state, receipt_digest,
            owner_id, epoch
     FROM subject_key_deletion_receipts
     WHERE request_digest = ?1
     ORDER BY artifact, artifact_identity
     LIMIT 4099";

/// The most rows a request may hold; more is a corrupt table and fails closed.
const MAX_RECEIPT_ROWS: usize = 4_098;

const ROW_STATE_SQL: &str = "SELECT state, receipt_digest, owner_id, epoch
     FROM subject_key_deletion_receipts
     WHERE request_digest = ?1 AND artifact = ?2 AND artifact_identity = ?3";

/// Writes the `Started` row. An existing row of any state is left as it is.
const INSERT_STARTED_SQL: &str = "INSERT INTO subject_key_deletion_receipts
         (request_digest, owner_id, epoch, artifact, artifact_identity, state, receipt_digest)
     VALUES (?1, ?2, ?3, ?4, ?5, 1, NULL)
     ON CONFLICT (request_digest, artifact, artifact_identity) DO NOTHING";

const CONFIRM_SQL: &str = "UPDATE subject_key_deletion_receipts
     SET state = 2, receipt_digest = ?4
     WHERE request_digest = ?1 AND artifact = ?2 AND artifact_identity = ?3 AND state = 1";

/// The fixed one-byte `artifact_identity` of an absent-at-start artifact.
pub const ABSENT_AT_START_IDENTITY: [u8; 1] = [0];

/// The kind of artifact one receipt row covers (D1 `artifact` column).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyDeletionArtifactV1 {
    /// A `SubjectKeyWrapV1` file.
    Wrap = 1,
    /// A `SubjectCredentialBindingV1` file.
    Binding = 2,
    /// The SNL1 nonce-ledger row.
    Snl1Row = 3,
}

impl SubjectKeyDeletionArtifactV1 {
    /// Every kind. Finalization needs at least one row of each.
    pub const ALL: [Self; 3] = [Self::Wrap, Self::Binding, Self::Snl1Row];

    const fn code(self) -> u8 {
        self as u8
    }

    const fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(Self::Wrap),
            2 => Some(Self::Binding),
            3 => Some(Self::Snl1Row),
            _ => None,
        }
    }
}

/// The recorded state of one receipt row (D1 `state` column).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyDeletionStateV1 {
    /// The `Started` row is committed; the deletion may be in flight.
    Started,
    /// The deletion is confirmed, with this receipt digest.
    Confirmed(Hash),
}

/// One durable receipt row of a destruction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyDeletionRowV1 {
    /// The kind of artifact.
    pub artifact: SubjectKeyDeletionArtifactV1,
    /// The file identity, the SNL1 row key or [`ABSENT_AT_START_IDENTITY`].
    pub artifact_identity: Vec<u8>,
    /// The recorded state.
    pub state: SubjectKeyDeletionStateV1,
}

/// The D1 `request_digest` of a destruction request.
#[must_use]
pub fn subject_key_destruction_request_digest(request: &KeyDestructionRequestV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/subject-key-destruction-request/v1\0");
    hasher.update(deletion_receipt(request).as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// The D1 `receipt_digest` of one artifact.
///
/// `absence_evidence` is the directory-relative `ENOENT` observation for a
/// file, the SHA-256 of the read-back ledger bytes for the SNL1 row, or the
/// digest of the sorted inventory listing for an absent-at-start kind. The
/// inputs are concatenated as ADR-137 D1 writes them, the artifact as its
/// one-byte code.
#[must_use]
pub fn subject_key_deletion_receipt_digest(
    request_digest: &Hash,
    artifact: SubjectKeyDeletionArtifactV1,
    artifact_identity: &[u8],
    absence_evidence: &[u8],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/subject-key-deletion-receipt/v1\0");
    hasher.update(request_digest.as_bytes());
    hasher.update(&[artifact.code()]);
    hasher.update(artifact_identity);
    hasher.update(absence_evidence);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn refusal(message: &str) -> CoreError {
    CoreError::Storage(message.to_owned())
}

const STORE_FAILED: &str = "subject key deletion receipt store failed";
const OUTCOME_UNKNOWN: &str = "subject key deletion commit outcome is unknown";

/// Map a `SQLite` result to the fixed receipt-store error, never echoing
/// paths or OS diagnostics.
fn stored<T>(result: rusqlite::Result<T>) -> Result<T, CoreError> {
    result.map_err(|_| refusal(STORE_FAILED))
}

/// Replace the text of an error from outside this module with a fixed one.
///
/// Typed refusals pass through, and an unknown commit outcome stays
/// `StorageOutcomeUnknown` so the owner can still quarantine its context.
fn sealed(error: CoreError) -> CoreError {
    match error {
        CoreError::Storage(_) => refusal(STORE_FAILED),
        CoreError::StorageOutcomeUnknown(_) => {
            CoreError::StorageOutcomeUnknown(OUTCOME_UNKNOWN.to_owned())
        }
        other => other,
    }
}

/// Finish the transaction scope, sealing every error that `SQLite` text can
/// reach: the commit or release failure and an unknown rollback outcome.
/// The error of a failed operation was sealed or fixed by its producer.
fn finish_scope<T>(
    conn: &Connection,
    scope: SqliteImmediateScopeV1,
    result: Result<T, CoreError>,
) -> Result<T, CoreError> {
    let operation_failed = result.is_err();
    finish_immediate_scope(conn, scope, result).map_err(|error| {
        if operation_failed && !matches!(error, CoreError::StorageOutcomeUnknown(_)) {
            error
        } else {
            sealed(error)
        }
    })
}

/// The identity a request binds to its rows: the digest that keys them and
/// the owner and epoch every row must repeat.
struct ReceiptBinding<'a> {
    request_digest: Hash,
    owner_id: &'a str,
    epoch: i64,
}

impl<'a> ReceiptBinding<'a> {
    fn of(request: &'a KeyDestructionRequestV1) -> Result<Self, CoreError> {
        i64::try_from(request.identity.epoch)
            .map_err(|_| refusal("subject key deletion epoch is out of range"))
            .map(|epoch| Self {
                request_digest: subject_key_destruction_request_digest(request),
                owner_id: request.identity.owner_id.as_str(),
                epoch,
            })
    }

    /// Refuse a row stored for another owner or epoch than the request's.
    fn check_row(&self, owner_id: &str, epoch: i64) -> Result<(), CoreError> {
        if owner_id == self.owner_id && epoch == self.epoch {
            Ok(())
        } else {
            Err(refusal(
                "subject key deletion receipt row belongs to another owner or epoch",
            ))
        }
    }
}

fn malformed_row() -> CoreError {
    refusal("subject key deletion receipt row is malformed")
}

fn require_subject_data_encryption(request: &KeyDestructionRequestV1) -> Result<(), CoreError> {
    if request.identity.role == KeyRoleV1::SubjectDataEncryption {
        Ok(())
    } else {
        Err(refusal(
            "subject key deletion receipts apply to SubjectDataEncryption only",
        ))
    }
}

fn parse_state(
    state: i64,
    receipt_digest: Option<Vec<u8>>,
) -> Result<SubjectKeyDeletionStateV1, CoreError> {
    match (state, receipt_digest) {
        (1, None) => Ok(SubjectKeyDeletionStateV1::Started),
        (2, Some(digest)) => <[u8; 32]>::try_from(digest)
            .map(|bytes| SubjectKeyDeletionStateV1::Confirmed(Hash::from_bytes(bytes)))
            .map_err(|_| malformed_row()),
        _ => Err(malformed_row()),
    }
}

type RawRowV1 = (i64, Vec<u8>, i64, Option<Vec<u8>>, String, i64);

fn parse_row(
    binding: &ReceiptBinding<'_>,
    (artifact, artifact_identity, state, receipt_digest, owner_id, epoch): RawRowV1,
) -> Result<SubjectKeyDeletionRowV1, CoreError> {
    binding
        .check_row(&owner_id, epoch)
        .and_then(|()| SubjectKeyDeletionArtifactV1::from_code(artifact).ok_or_else(malformed_row))
        .and_then(|artifact| {
            parse_state(state, receipt_digest).map(|state| SubjectKeyDeletionRowV1 {
                artifact,
                artifact_identity,
                state,
            })
        })
}

fn is_absent_at_start(row: &SubjectKeyDeletionRowV1) -> bool {
    row.artifact_identity == ABSENT_AT_START_IDENTITY
}

/// Require that every row is `Confirmed`, that each kind has a row and that
/// no kind holds both an absent-at-start row and a real artifact.
fn require_complete(rows: &[SubjectKeyDeletionRowV1]) -> Result<(), CoreError> {
    if !rows
        .iter()
        .all(|row| matches!(row.state, SubjectKeyDeletionStateV1::Confirmed(_)))
    {
        return Err(refusal(
            "subject key deletion receipts are not all confirmed",
        ));
    }
    if !SubjectKeyDeletionArtifactV1::ALL
        .iter()
        .all(|kind| rows.iter().any(|row| row.artifact == *kind))
    {
        return Err(refusal(
            "subject key deletion receipts miss an artifact kind",
        ));
    }
    let mixed = SubjectKeyDeletionArtifactV1::ALL.iter().any(|kind| {
        let of_kind = || rows.iter().filter(|row| row.artifact == *kind);
        of_kind().any(is_absent_at_start) && of_kind().any(|row| !is_absent_at_start(row))
    });
    if mixed {
        return Err(refusal(
            "subject key deletion receipts mix an absent and a present artifact of one kind",
        ));
    }
    Ok(())
}

fn read_request_rows(
    conn: &Connection,
    request: &KeyDestructionRequestV1,
) -> Result<Vec<SubjectKeyDeletionRowV1>, CoreError> {
    let binding = ReceiptBinding::of(request)?;
    let mut statement = stored(conn.prepare(REQUEST_ROWS_SQL))?;
    let raw = stored(
        statement
            .query_map(
                params![binding.request_digest.as_bytes().as_slice()],
                |row| RawRowV1::try_from(row),
            )
            .and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>),
    )?;
    if raw.len() > MAX_RECEIPT_ROWS {
        return Err(refusal("subject key deletion receipts exceed the bound"));
    }
    raw.into_iter()
        .map(|row| parse_row(&binding, row))
        .collect()
}

type RawStateV1 = (i64, Option<Vec<u8>>, String, i64);

fn read_row_state(
    conn: &Connection,
    binding: &ReceiptBinding<'_>,
    artifact: SubjectKeyDeletionArtifactV1,
    artifact_identity: &[u8],
) -> Result<Option<SubjectKeyDeletionStateV1>, CoreError> {
    stored(
        conn.query_row(
            ROW_STATE_SQL,
            params![
                binding.request_digest.as_bytes().as_slice(),
                i64::from(artifact.code()),
                artifact_identity
            ],
            |row| RawStateV1::try_from(row),
        )
        .optional(),
    )
    .and_then(|row| {
        row.map(|(state, receipt_digest, owner_id, epoch)| {
            binding
                .check_row(&owner_id, epoch)
                .and_then(|()| parse_state(state, receipt_digest))
        })
        .transpose()
    })
}

impl SqliteStore {
    /// Create the D1 table on a writable open, then validate its exact shape.
    pub(super) fn prepare_subject_key_deletion_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&sqlite_schema_ddl(SUBJECT_KEY_DELETION_SCHEMA_TABLES))
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                SUBJECT_KEY_DELETION_SCHEMA_TABLES
                    .iter()
                    .try_for_each(|table| self.validate_sqlite_schema_table(table))
            })
    }

    /// Require that the registry holds exactly `request` as pending.
    ///
    /// A `Started` or `Confirmed` row is only meaningful after the D2 step 2
    /// `DestructionPending` commit, so any other registry state refuses.
    fn require_pending_destruction(
        &self,
        request: &KeyDestructionRequestV1,
    ) -> Result<(), CoreError> {
        self.load_key_registry()
            .map_err(sealed)
            .and_then(|registry| {
                registry.ok_or_else(|| refusal("durable key registry is unavailable"))
            })
            .and_then(|registry| {
                if registry
                    .pending_destruction_requests()
                    .any(|pending| pending == *request)
                {
                    Ok(())
                } else {
                    Err(refusal("subject key destruction is not pending"))
                }
            })
    }

    /// Like [`Self::require_pending_destruction`], but a request whose
    /// tombstone is already committed also passes, so a repeated finalization
    /// reaches the registry's `AlreadyDestroyed` outcome.
    fn require_pending_or_destroyed(
        &self,
        request: &KeyDestructionRequestV1,
    ) -> Result<(), CoreError> {
        let destroyed = self
            .load_key_registry()
            .map_err(sealed)?
            .is_some_and(|registry| registry.tombstone(request.identity).is_some());
        if destroyed {
            Ok(())
        } else {
            self.require_pending_destruction(request)
        }
    }

    /// Run one receipt write inside its own `BEGIN IMMEDIATE`.
    ///
    /// The write runs only for a `SubjectDataEncryption` request that the
    /// registry holds as `DestructionPending`, after the inventory data
    /// version check that every other durable write makes.
    fn write_subject_key_deletion<T>(
        &self,
        request: &KeyDestructionRequestV1,
        write: impl FnOnce(&Self, &ReceiptBinding<'_>) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        require_subject_data_encryption(request)?;
        let binding = ReceiptBinding::of(request)?;
        let scope = begin_immediate_scope(&self.conn).map_err(sealed)?;
        let result = self
            .validate_erasure_inventory_data_version()
            .map_err(sealed)
            .and_then(|()| self.require_pending_destruction(request))
            .and_then(|()| write(self, &binding));
        finish_scope(&self.conn, scope, result)
    }

    /// Commit the `Started` row of one artifact (D2 steps 4 and 5).
    ///
    /// Returns only after the row is durably committed, which is the
    /// precondition for the owner to unlink the file or replace the ledger.
    /// Repeating the call for an existing row of any state is a no-op.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, when the request is not a
    /// `SubjectDataEncryption` request that the registry holds as pending,
    /// when the row exists for another owner or epoch, or when the write
    /// fails. An error carrying an unknown commit outcome must
    /// quarantine the owner's context.
    pub fn record_subject_key_deletion_started(
        &self,
        request: &KeyDestructionRequestV1,
        artifact: SubjectKeyDeletionArtifactV1,
        artifact_identity: &[u8],
    ) -> Result<(), CoreError> {
        self.write_subject_key_deletion(request, |store, binding| {
            stored(store.conn.execute(
                INSERT_STARTED_SQL,
                params![
                    binding.request_digest.as_bytes().as_slice(),
                    binding.owner_id,
                    binding.epoch,
                    i64::from(artifact.code()),
                    artifact_identity
                ],
            ))
            .and_then(|_| read_row_state(&store.conn, binding, artifact, artifact_identity))
            .map(|_| ())
        })
    }

    /// Commit `Confirmed` on a `Started` row and return its receipt digest.
    ///
    /// Repeating the call with the same evidence returns the same digest.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, when the request is not pending,
    /// when the row was never started, when it is already confirmed with
    /// different evidence, or when the write fails.
    pub fn confirm_subject_key_deletion(
        &self,
        request: &KeyDestructionRequestV1,
        artifact: SubjectKeyDeletionArtifactV1,
        artifact_identity: &[u8],
        absence_evidence: &[u8],
    ) -> Result<Hash, CoreError> {
        self.write_subject_key_deletion(request, |store, binding| {
            let receipt = subject_key_deletion_receipt_digest(
                &binding.request_digest,
                artifact,
                artifact_identity,
                absence_evidence,
            );
            read_row_state(&store.conn, binding, artifact, artifact_identity).and_then(|state| {
                match state {
                    None => Err(refusal("subject key deletion was not started")),
                    Some(SubjectKeyDeletionStateV1::Confirmed(recorded)) if recorded == receipt => {
                        Ok(receipt)
                    }
                    Some(SubjectKeyDeletionStateV1::Confirmed(_)) => Err(refusal(
                        "subject key deletion is confirmed with other evidence",
                    )),
                    Some(SubjectKeyDeletionStateV1::Started) => stored(store.conn.execute(
                        CONFIRM_SQL,
                        params![
                            binding.request_digest.as_bytes().as_slice(),
                            i64::from(artifact.code()),
                            artifact_identity,
                            receipt.as_bytes().as_slice()
                        ],
                    ))
                    .map(|_| receipt),
                }
            })
        })
    }

    /// Read every receipt row of `request`, ordered by kind and identity.
    ///
    /// The Gateway composition may call this as evidence; it cannot write.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, when the rows cannot be read, when
    /// a row does not parse, or when the request holds more than the bound.
    pub fn subject_key_deletion_receipts(
        &self,
        request: &KeyDestructionRequestV1,
    ) -> Result<Vec<SubjectKeyDeletionRowV1>, CoreError> {
        read_request_rows(&self.conn, request)
    }

    /// Finalize a subject-key destruction (D2 step 6).
    ///
    /// In one `BEGIN IMMEDIATE`, requires every receipt row of the request to
    /// be `Confirmed` with at least one row of each kind and no kind mixing an
    /// absent-at-start row with a real artifact, then applies exactly
    /// the `complete_key_registry_destruction(request, deletion_receipt)`
    /// registry transition in the same commit. A repeated call after the
    /// tombstone returns the registry's `AlreadyDestroyed` outcome.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, when the request is not a
    /// `SubjectDataEncryption` request, when a receipt is missing or not
    /// confirmed, when a kind mixes absent and present rows, when the
    /// registry holds the request as neither pending nor destroyed, or when
    /// the registry transition fails. Nothing is committed on error.
    pub fn complete_subject_key_destruction_with_receipts(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<(KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
        require_subject_data_encryption(&request)?;
        let scope = begin_immediate_scope(&self.conn).map_err(sealed)?;
        let result = self
            .validate_erasure_inventory_data_version()
            .map_err(sealed)
            .and_then(|()| self.require_pending_or_destroyed(&request))
            .and_then(|()| read_request_rows(&self.conn, &request))
            .and_then(|rows| require_complete(&rows))
            .and_then(|()| {
                EventStore::complete_key_registry_destruction(
                    self,
                    request,
                    deletion_receipt(&request),
                )
                .map_err(sealed)
            });
        finish_scope(&self.conn, scope, result)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
