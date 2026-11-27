#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-137 P1, P3, P3a and P5 durable key staging, plus the D4 enumeration.
//!
//! Enrolling a subject key stages an attempt in the bound store before any
//! artifact is written, and registers the identity in one linearizing
//! commit. This module owns the shared-store half of that flow:
//!
//! - the `subject_key_staging` table (P3a), one row per staged and
//!   unregistered `(owner_id, epoch)` of this store, naming the store;
//! - [`SqliteStore::subject_registry_epoch_ceiling`], the P1 read of P3 step 2;
//! - [`SqliteStore::commit_subject_key_staging_record`], P3 step 3;
//! - [`SqliteStore::register_subject_key`], the P3 step 6 linearization point,
//!   which registers, activates and deletes the record in one commit;
//! - [`SqliteStore::delete_subject_key_staging_record`], the last step of P5
//!   for one of this store's own attempts;
//! - [`SqliteStore::recover_subject_key_staging`], the store half of P5 at
//!   owner start;
//! - [`SqliteStore::subject_key_lifecycle`] and
//!   [`SqliteStore::registered_subject_root_material_digest`], the P1 reads
//!   that P5 and ADR-097 section 5 unlock use;
//! - [`SqliteStore::pending_subject_key_destructions`], the D4 enumeration of
//!   subject keys and timeline signing keys.
//!
//! The wrap and binding files, the SNL1 row, the E16 and subject-owner locks
//! and the order of the readiness steps (R2: P5 before D4) belong to the owner
//! adapter, which calls these methods. The adapter lives in
//! `pos-owner-adapter`, which this crate must not depend on, so the methods
//! take and return plain values and the adapter maps them onto its
//! `EnrollmentStore` and `UnlockStore` traits.
//!
//! Only the owner process writes the table; the Gateway composition has no API
//! that does. Everything here stays test-support gated until owner activation
//! (#1438). Only a writable open creates and validates the table, so a
//! read-only open never creates it. Ungating in #1438 must remove both `cfg`
//! gates together, this module's and the writable-open call in `sqlite.rs`.
//!
//! Every failure carries one of two fixed messages, never a path, an OS
//! diagnostic or a key digest. An unknown commit outcome stays
//! [`CoreError::StorageOutcomeUnknown`] so that the owner can quarantine its
//! context and leave the attempt to P5 at the next start.

use pos_core::{
    error::CoreError, ids::TimelineId, EventStore, Hash, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, OwnerIdV1,
};
use rusqlite::{params, Connection};

use super::erasure_fence_rows::require_no_erasure_fence_rows;
use super::{
    begin_immediate_scope, finish_immediate_scope, sqlite_schema_ddl, SqliteSchemaColumn,
    SqliteSchemaTable, SqliteStore,
};

/// The P3a table, keyed by `(owner_id, epoch)`.
///
/// The builder creates a non-`STRICT` table, so the `typeof` checks give the
/// same column typing that `STRICT` would. The owner checks pin the ADR-091
/// owner: `subject:` and 32 lowercase hex digits. The `store_file_id` is the
/// SNL1 store-file encoding, which is at most 20 bytes for either platform;
/// the table admits the ADR's 32 and refuses an empty value, which no proven
/// store identity has.
const SUBJECT_KEY_STAGING_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "subject_key_staging",
    columns_query: "PRAGMA table_info(subject_key_staging)",
    columns: &[
        SqliteSchemaColumn {
            name: "owner_id",
            kind: "TEXT",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "epoch",
            kind: "INTEGER",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "store_file_id",
            kind: "BLOB",
            not_null: true,
            primary_key: false,
        },
    ],
    constraints: &[
        "CHECK (typeof(owner_id) = 'text')",
        "CHECK (length(owner_id) = 40)",
        "CHECK (substr(owner_id, 1, 8) = 'subject:')",
        "CHECK (substr(owner_id, 9) NOT GLOB '*[^0-9a-f]*')",
        "CHECK (typeof(epoch) = 'integer')",
        "CHECK (epoch >= 1)",
        "CHECK (typeof(store_file_id) = 'blob')",
        "CHECK (length(store_file_id) BETWEEN 1 AND 32)",
    ],
}];

/// The most staging rows one recovery reads. The table holds at most one row
/// per subject in practice (P3a), so more is a corrupt table and fails closed.
const MAX_STAGING_RECORDS: usize = 4_096;

const STAGING_ROWS_SQL: &str = "SELECT owner_id, epoch, store_file_id
     FROM subject_key_staging
     ORDER BY owner_id, epoch
     LIMIT 4097";

const INSERT_SQL: &str = "INSERT INTO subject_key_staging (owner_id, epoch, store_file_id)
     VALUES (?1, ?2, ?3)";

/// Deletes exactly one store's record, so a claim is never released for
/// another store.
const DELETE_SQL: &str = "DELETE FROM subject_key_staging
     WHERE owner_id = ?1 AND epoch = ?2 AND store_file_id = ?3";

const REFUSED: &str = "subject key staging was refused";
const OUTCOME_UNKNOWN: &str = "subject key staging commit outcome is unknown";

/// The longest SNL1 `store_file_id` encoding the table admits.
const MAX_STORE_FILE_ID_BYTES: usize = 32;

/// One P3a staging record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyStagingRecordV1 {
    /// The ADR-091 owner: `subject:` and 32 lowercase hex digits.
    pub owner_id: String,
    /// The staged epoch, at least 1.
    pub epoch: u64,
    /// The SNL1 `store_file_id` encoding of the store that staged the attempt.
    pub store_file_id: Vec<u8>,
}

/// The registry role of the owner process's own signing identity.
const OWNER_SIGNING_ROLE: KeyRoleV1 = KeyRoleV1::TimelineIntegritySigning;

/// The `DestructionPending` requests that ADR-137 D4 resumes at owner start.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingKeyDestructionsV1 {
    /// Every `SubjectDataEncryption` request, of any subject and epoch.
    pub subject_keys: Vec<KeyDestructionRequestV1>,
    /// Every `TimelineIntegritySigning` request, of any owner id and epoch.
    /// The caller keeps the requests of its own signing identity.
    pub signing_keys: Vec<KeyDestructionRequestV1>,
}

/// The P1 lifecycle of one `SubjectDataEncryption` identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyLifecycleV1 {
    /// The registry holds no record of the identity.
    Absent,
    /// Registered and live, active or retained for historical decryption,
    /// with the ADR-091 `key_material_digest` of its root.
    Live(Hash),
    /// A destruction request is pending (ADR-065, ADR-097 section 5).
    DestructionPending,
    /// The identity was destroyed and holds a tombstone.
    Destroyed,
}

fn refusal() -> CoreError {
    CoreError::Storage(REFUSED.to_owned())
}

/// Replace the text of any error with a fixed one.
///
/// An unknown commit outcome stays unknown. Every other error, including a
/// typed one, becomes the fixed refusal, so no `SQLite` text escapes.
fn sealed(error: &CoreError) -> CoreError {
    match error {
        CoreError::StorageOutcomeUnknown(_) => {
            CoreError::StorageOutcomeUnknown(OUTCOME_UNKNOWN.to_owned())
        }
        _ => refusal(),
    }
}

/// Map a `SQLite` result to the fixed refusal.
fn stored<T>(result: rusqlite::Result<T>) -> Result<T, CoreError> {
    result.map_err(|_| refusal())
}

/// The registry owner of an ADR-091 subject: `subject:` and 32 lowercase hex
/// digits that are not all zero (a non-nil subject).
///
/// Only this API refuses the nil subject; the table's `CHECK`s pin the
/// `subject:` plus 32 lowercase hex form and do not exclude the nil value.
fn subject_owner(owner_id: &str) -> Result<OwnerIdV1, CoreError> {
    owner_id
        .strip_prefix("subject:")
        .filter(|digits| {
            digits.len() == 32
                && digits
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                && digits.bytes().any(|byte| byte != b'0')
        })
        .and_then(|_| OwnerIdV1::new(owner_id).ok())
        .ok_or_else(refusal)
}

/// The positive epoch as the `SQLite` integer the table stores.
fn stored_epoch(epoch: u64) -> Result<i64, CoreError> {
    i64::try_from(epoch)
        .ok()
        .filter(|stored| *stored >= 1)
        .ok_or_else(refusal)
}

/// Require a store-file encoding the table can hold.
fn checked_store_file_id(bytes: &[u8]) -> Result<&[u8], CoreError> {
    Some(bytes)
        .filter(|bytes| (1..=MAX_STORE_FILE_ID_BYTES).contains(&bytes.len()))
        .ok_or_else(refusal)
}

/// The identity of a `SubjectDataEncryption` owner and epoch.
fn identity_of(owner: OwnerIdV1, epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new(owner, KeyRoleV1::SubjectDataEncryption, epoch)
}

/// The P1 lifecycle of `identity` in `registry`.
fn lifecycle_in(registry: &KeyRegistryStateV1, identity: KeyIdentityV1) -> SubjectKeyLifecycleV1 {
    registry
        .key_record(identity)
        .map_or(SubjectKeyLifecycleV1::Absent, |record| {
            if registry
                .pending_destruction_requests()
                .any(|request| request.identity == identity)
            {
                SubjectKeyLifecycleV1::DestructionPending
            } else {
                record.private_material_digest.map_or(
                    SubjectKeyLifecycleV1::Destroyed,
                    SubjectKeyLifecycleV1::Live,
                )
            }
        })
}

type RawRowV1 = (String, i64, Vec<u8>);

/// One parsed staging row with the forms the store's own calls need.
struct StagedRowV1 {
    owner: OwnerIdV1,
    stored_epoch: i64,
    record: SubjectKeyStagingRecordV1,
}

/// Parse one stored row, refusing a row that the table's checks would have
/// refused: a malformed row makes P1 unreadable and fails closed.
fn parse_row((owner_id, stored_epoch, store_file_id): RawRowV1) -> Result<StagedRowV1, CoreError> {
    subject_owner(&owner_id).and_then(|owner| {
        u64::try_from(stored_epoch)
            .ok()
            .filter(|epoch| *epoch >= 1)
            .filter(|_| checked_store_file_id(&store_file_id).is_ok())
            .map(|epoch| StagedRowV1 {
                owner,
                stored_epoch,
                record: SubjectKeyStagingRecordV1 {
                    owner_id,
                    epoch,
                    store_file_id,
                },
            })
            .ok_or_else(refusal)
    })
}

/// Read every staging row, in `(owner_id, epoch)` order, at most the bound.
fn read_staging_rows(conn: &Connection) -> Result<Vec<StagedRowV1>, CoreError> {
    stored(conn.prepare(STAGING_ROWS_SQL))
        .and_then(|mut statement| {
            // A path (`RawRowV1::try_from`) cannot stand in for this closure:
            // the `TryFrom<&Row<'_>>` impl's lifetime is early-bound, so the
            // path is not higher-ranked over the row borrow.
            let rows = statement
                .query_map([], |row| RawRowV1::try_from(row))
                .and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>);
            stored(rows)
        })
        .and_then(|raw| {
            (raw.len() <= MAX_STAGING_RECORDS)
                .then_some(raw)
                .ok_or_else(refusal)
        })
        .and_then(|raw| raw.into_iter().map(parse_row).collect())
}

/// Delete exactly the record `(owner_id, epoch, store_file_id)` and report
/// whether it existed.
fn delete_record(
    conn: &Connection,
    owner_id: &str,
    epoch: i64,
    store_file_id: &[u8],
) -> Result<bool, CoreError> {
    stored(conn.execute(DELETE_SQL, params![owner_id, epoch, store_file_id]))
        .map(|deleted| deleted == 1)
}

impl SqliteStore {
    /// Create the P3a table on a writable open, then validate its exact shape.
    pub(super) fn prepare_subject_key_staging_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&sqlite_schema_ddl(SUBJECT_KEY_STAGING_SCHEMA_TABLES))
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                SUBJECT_KEY_STAGING_SCHEMA_TABLES
                    .iter()
                    .try_for_each(|table| self.validate_sqlite_schema_table(table))
            })
    }

    /// Load the durable registry (P1), refusing when it is absent or unreadable.
    ///
    /// P1 is never treated as empty: a store whose registry cannot be read
    /// refuses, and so does one that holds no registry row at all. ADR-137
    /// P6's "P2 with an empty P1" is a registry that exists and holds no
    /// `SubjectDataEncryption` identity, which every method here reads as an
    /// empty set. A store with no registry row has never registered even the
    /// owner's signing identity, so it is not a provisioned owner store.
    fn available_subject_registry(&self) -> Result<KeyRegistryStateV1, CoreError> {
        self.load_key_registry()
            .and_then(|registry| registry.ok_or_else(refusal))
    }

    /// Run `operation` inside this store's own `BEGIN IMMEDIATE`.
    ///
    /// The caller must hold no transaction on the connection: a savepoint
    /// inside an outer transaction would return before its writes are durable.
    /// The inventory data version check that every other durable write makes
    /// runs first. Each error is sealed to a fixed message.
    fn staging_transaction<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, CoreError>,
    ) -> Result<T, CoreError> {
        if !self.conn.is_autocommit() {
            return Err(refusal());
        }
        begin_immediate_scope(&self.conn)
            .map_err(|error| sealed(&error))
            .and_then(|scope| {
                let result = self
                    .validate_erasure_inventory_data_version()
                    .and_then(|()| operation(self));
                finish_immediate_scope(&self.conn, scope, result).map_err(|error| sealed(&error))
            })
    }

    /// The P1 epoch ceiling of P3 step 2, and the P5 re-read before a delete.
    ///
    /// In one `BEGIN IMMEDIATE`, refuse when a B6 row fences the subject's
    /// `timeline`, then return the highest epoch or high-water entry that the
    /// registry holds for `owner_id`'s `SubjectDataEncryption` role in any
    /// lifecycle state, or zero when it holds none.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an `owner_id` that is not an
    /// ADR-091 subject owner, a B6 fence of any kind (including an unreadable
    /// or malformed fence row), an absent or unreadable registry, a caller
    /// that holds a transaction, and a failed read.
    pub fn subject_registry_epoch_ceiling(
        &self,
        owner_id: &str,
        timeline: TimelineId,
    ) -> Result<u64, CoreError> {
        subject_owner(owner_id).and_then(|owner| {
            self.staging_transaction(|store| {
                require_no_erasure_fence_rows(&store.conn, timeline)
                    .map_err(|_| refusal())
                    .and_then(|()| store.available_subject_registry())
                    .map(|registry| {
                        registry
                            .highest_epoch(&owner, KeyRoleV1::SubjectDataEncryption)
                            .unwrap_or_default()
                    })
            })
        })
    }

    /// P3 step 3: commit the staging record `(owner_id, epoch, store_file_id)`.
    ///
    /// In one `BEGIN IMMEDIATE`, insert the record for the bound store.
    /// `store_file_id` is the SNL1 encoding of the store's proven file
    /// identity (ADR-123 section 5), which the SNL1 row of step 5 carries. No
    /// artifact may be written before this commit returns.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an `owner_id` that is not an
    /// ADR-091 subject owner, an epoch below 1 or above `i64::MAX`, an empty
    /// or over-long `store_file_id`, a record that already exists for
    /// `(owner_id, epoch)` (whichever store it names), a caller that holds a
    /// transaction, and a failed write. Nothing is staged after a failure.
    pub fn commit_subject_key_staging_record(
        &self,
        owner_id: &str,
        epoch: u64,
        store_file_id_bytes: &[u8],
    ) -> Result<(), CoreError> {
        subject_owner(owner_id)
            .and_then(|_| stored_epoch(epoch))
            .and_then(|epoch| checked_store_file_id(store_file_id_bytes).map(|id| (epoch, id)))
            .and_then(|(epoch, id)| {
                self.staging_transaction(|store| {
                    stored(store.conn.execute(INSERT_SQL, params![owner_id, epoch, id])).map(|_| ())
                })
            })
    }

    /// P3 step 6, the linearization point: register, activate and unstage.
    ///
    /// In one `BEGIN IMMEDIATE`, in this order: re-check the B6 rows of
    /// `timeline`; re-read the registry and require `epoch` to be strictly
    /// above the owner's high-water mark; register and activate the identity
    /// under the ADR-065 rules, retaining a previous epoch for decryption
    /// only; delete the staging record `(owner_id, epoch, store_file_id)`;
    /// commit. The record must exist and name `store_file_id`, so a foreign
    /// record can never register.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an `owner_id` that is not an
    /// ADR-091 subject owner, an invalid epoch or `store_file_id`, a B6 fence,
    /// an absent or unreadable registry, an epoch at or below the high-water
    /// mark, a missing record or one that names another store, material that
    /// the registry already reserves, a caller that holds a transaction, and
    /// a failed write. A failed commit may carry an unknown outcome, which
    /// stays [`CoreError::StorageOutcomeUnknown`]; the owner then deletes
    /// nothing and leaves the attempt to P5 at its next start.
    pub fn register_subject_key(
        &self,
        owner_id: &str,
        timeline: TimelineId,
        epoch: u64,
        store_file_id_bytes: &[u8],
        root_material_digest: Hash,
    ) -> Result<(), CoreError> {
        subject_owner(owner_id)
            .and_then(|owner| stored_epoch(epoch).map(|stored| (owner, stored)))
            .and_then(|(owner, stored)| {
                checked_store_file_id(store_file_id_bytes).map(|id| (owner, stored, id))
            })
            .and_then(|(owner, stored, id)| {
                self.staging_transaction(|store| {
                    require_no_erasure_fence_rows(&store.conn, timeline)
                        .map_err(|_| refusal())
                        .and_then(|()| store.available_subject_registry())
                        .and_then(|mut registry| {
                            registry
                                .highest_epoch(&owner, KeyRoleV1::SubjectDataEncryption)
                                .is_none_or(|highest| epoch > highest)
                                .then(|| {
                                    registry.register_key(KeyRegistrationV1::new(
                                        identity_of(owner, epoch),
                                        root_material_digest,
                                        None,
                                    ))
                                })
                                .and_then(Result::ok)
                                .map(|_| registry)
                                .ok_or_else(refusal)
                        })
                        .and_then(|registry| store.save_key_registry_in_transaction(&registry))
                        .and_then(|()| delete_record(&store.conn, owner_id, stored, id))
                        .and_then(|deleted| deleted.then_some(()).ok_or_else(refusal))
                })
            })
    }

    /// The last step of P5 for one of this store's own attempts: delete the
    /// staging record `(owner_id, epoch, store_file_id)`.
    ///
    /// In one `BEGIN IMMEDIATE`, delete exactly that record. A missing record
    /// is an idempotent success, and a record that names another store is left
    /// alone, so a claim is never released for another store. The owner calls
    /// this only after P5 has deleted or deliberately kept the attempt's files
    /// and SNL1 row.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an `owner_id` that is not an
    /// ADR-091 subject owner, an invalid epoch or `store_file_id`, a caller
    /// that holds a transaction, and a failed write. The record then stays for
    /// P5 recovery.
    pub fn delete_subject_key_staging_record(
        &self,
        owner_id: &str,
        epoch: u64,
        store_file_id_bytes: &[u8],
    ) -> Result<(), CoreError> {
        subject_owner(owner_id)
            .and_then(|_| stored_epoch(epoch))
            .and_then(|epoch| checked_store_file_id(store_file_id_bytes).map(|id| (epoch, id)))
            .and_then(|(epoch, id)| {
                self.staging_transaction(|store| {
                    delete_record(&store.conn, owner_id, epoch, id).map(|_| ())
                })
            })
    }

    /// The store half of ADR-137 P5 at owner start.
    ///
    /// In one `BEGIN IMMEDIATE`, read P1 and every staging record, then delete
    /// the records that need no file work:
    ///
    /// - a foreign record, whose `store_file_id` differs from the bound
    ///   store's, for example one carried into a copy of the store: only the
    ///   record is deleted;
    /// - an own record whose identity the registry holds in any state (not
    ///   reachable, because step 6 deletes the record atomically): only the
    ///   record is deleted, since the artifacts belong to a registered
    ///   identity.
    ///
    /// The remaining own records are orphans of this store, returned in
    /// `(owner_id, epoch)` order and left in the table. The owner applies the
    /// P5 SNL1 guard, deletes the wrap and binding files and the SNL1 row
    /// where the guard allows, and then calls
    /// [`Self::delete_subject_key_staging_record`] for each.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, and deletes nothing, for an empty
    /// or over-long `bound_store_file_id`, an absent or unreadable registry
    /// (readiness is refused, never treated as empty), a staging row that does
    /// not parse or more rows than the bound, a caller that holds a
    /// transaction, and a failed write.
    pub fn recover_subject_key_staging(
        &self,
        bound_store_file_id: &[u8],
    ) -> Result<Vec<SubjectKeyStagingRecordV1>, CoreError> {
        checked_store_file_id(bound_store_file_id).and_then(|bound| {
            self.staging_transaction(|store| {
                store.available_subject_registry().and_then(|registry| {
                    read_staging_rows(&store.conn).and_then(|rows| {
                        let (orphans, settled): (Vec<_>, Vec<_>) =
                            rows.into_iter().partition(|row| {
                                row.record.store_file_id == bound
                                    && lifecycle_in(
                                        &registry,
                                        identity_of(row.owner, row.record.epoch),
                                    ) == SubjectKeyLifecycleV1::Absent
                            });
                        settled
                            .iter()
                            .try_for_each(|row| {
                                delete_record(
                                    &store.conn,
                                    &row.record.owner_id,
                                    row.stored_epoch,
                                    &row.record.store_file_id,
                                )
                                .map(|_| ())
                            })
                            .map(|()| orphans.into_iter().map(|row| row.record).collect())
                    })
                })
            })
        })
    }

    /// The P1 lifecycle of the `SubjectDataEncryption` identity
    /// `(owner_id, epoch)`.
    ///
    /// One read of the registry. P5 classifies artifacts and rows against it.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an `owner_id` that is not an
    /// ADR-091 subject owner, an epoch below 1 or above `i64::MAX`, and an
    /// absent or unreadable registry.
    pub fn subject_key_lifecycle(
        &self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<SubjectKeyLifecycleV1, CoreError> {
        subject_owner(owner_id)
            .and_then(|owner| stored_epoch(epoch).map(|_| identity_of(owner, epoch)))
            .and_then(|identity| {
                self.available_subject_registry()
                    .map_err(|error| sealed(&error))
                    .map(|registry| lifecycle_in(&registry, identity))
            })
    }

    /// The root fingerprint of the exact live registry identity (ADR-097
    /// section 5 unlock).
    ///
    /// Returns the ADR-091 `key_material_digest` that the registry holds for
    /// `(owner_id, epoch)`, provided that identity is registered and live:
    /// active, or retained for historical decryption.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an absent, `DestructionPending`
    /// or `Destroyed` identity and for every error of
    /// [`Self::subject_key_lifecycle`].
    pub fn registered_subject_root_material_digest(
        &self,
        owner_id: &str,
        epoch: u64,
    ) -> Result<Hash, CoreError> {
        self.subject_key_lifecycle(owner_id, epoch)
            .and_then(|lifecycle| match lifecycle {
                SubjectKeyLifecycleV1::Live(digest) => Ok(digest),
                _ => Err(refusal()),
            })
    }

    /// The D4 enumeration: every `DestructionPending` request that startup
    /// recovery resumes, split by kind.
    ///
    /// The owner resumes each at step 3 of D2, idempotently, after SNL1
    /// admission and P5. A failure of one identity leaves it pending and does
    /// not block the others. Requests of every other role are not listed.
    ///
    /// ADR-137 D4 names no owner id or role for the owner's own signing
    /// identity, so this store does not pick one: `signing_keys` holds every
    /// pending `TimelineIntegritySigning` request and the caller must keep
    /// only those of its own owner id.
    ///
    /// # Errors
    /// Fails closed, with a fixed message, for an absent or unreadable
    /// registry.
    pub fn pending_subject_key_destructions(&self) -> Result<PendingKeyDestructionsV1, CoreError> {
        self.available_subject_registry()
            .map_err(|error| sealed(&error))
            .map(|registry| {
                let (subject_keys, others): (Vec<_>, Vec<_>) = registry
                    .pending_destruction_requests()
                    .partition(|request| request.identity.role == KeyRoleV1::SubjectDataEncryption);
                PendingKeyDestructionsV1 {
                    subject_keys,
                    signing_keys: others
                        .into_iter()
                        .filter(|request| request.identity.role == OWNER_SIGNING_ROLE)
                        .collect(),
                }
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
