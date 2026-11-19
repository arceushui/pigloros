//! Local recipient-export withdrawal for erasure (ADR-138) on the Linux
//! `SQLite` adapter.
//!
//! One withdrawal moves an export through `none → retracted → withdrawn`:
//!
//! - T1 records the withdrawal row, after which no serving read returns the
//!   publication, and captures the identity of its final and staging objects
//!   in the attached custody directory. The final object is hashed through
//!   its opened descriptor before the transaction begins.
//! - The owner step unlinks exactly the captured objects, syncs their
//!   directory, and T2 records the deletion.
//! - T3 deletes the catalog row and records `CA(ELXW1)` with the ELO1 that
//!   binds it, through `commit_local_owner_effect`.
//!
//! Every step commits on `self.conn` under `synchronous=FULL`, and is refused
//! on a read-only handle or inside an outer transaction (ADR-138 §3).
//!
//! The withdrawal table is created with the recipient-export catalog. A store
//! whose catalog predates it has no supported upgrade (no-legacy rule): its
//! reservation and serving reads fail closed with a storage error, and T1
//! cannot record a withdrawal there.

use std::{collections::BTreeSet, fs::File, io::Read};

use pos_core::{
    local_erasure_export_recipient_v1, recipient_owner_id_from_grantee, CoreError, EntityId,
    ErasureErrorV1, ErasureReferenceV1, ErasureRetainedObjectV1, Hash, OwnerIdV1,
    PreparedLocalOwnerEffectV1, RecipientExportWithdrawalBindingV1,
    RecipientExportWithdrawalStateV1,
};
use rusqlite::{params, Connection, OptionalExtension};
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};

use super::{
    claim_recipient_custody_directory, ensure_recipient_custody_tables,
    ensure_recipient_export_durability, is_safe_recipient_export_entry,
    load_recipient_export_catalog, recipient_export_final_name, recipient_export_staging_name,
    recipient_fsync, recipient_openat2, recipient_statat, recipient_unlinkat,
    restore_recipient_export_synchronous_level, storage_error, validate_owner_directory,
    validate_recipient_export_file, RecipientKeyOwnerV1, RecipientPrivateFileIdentityV1,
};
use crate::sqlite::{
    begin_immediate_sql, finish_erasure_transaction, load_sqlite_erasure_evidence,
    local_erasure::{insert_retained, table_present, RECIPIENT_EXPORT_WITHDRAWALS},
    map_erasure_receipt_failure, parse_timeline_id, reference_from_sql, SqliteRollbackOnDrop,
    SqliteStore,
};

/// Capture status: the final object, and any staging object, are captured.
const CAPTURED: u8 = 0;
/// Capture status: no usable custody is attached for the grantee.
const NO_CUSTODY: u8 = 1;
/// Capture status: the final object is absent from the attached directory.
const FINAL_MISSING: u8 = 2;
/// Capture status: the final or staging object is unsafe, or the final
/// object's length or digest differs from the catalog's.
const UNSAFE: u8 = 3;

/// Every custody object open here: read-only, non-blocking and never through
/// a link.
const OBJECT_OPEN: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW);
/// Every custody object name resolves beneath its directory only.
const OBJECT_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Why [`SqliteStore::attach_recipient_custody`] refused; nothing was
/// attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecipientCustodyAttachErrorV1 {
    /// Two handles name one grantee.
    #[error("two recipient custody handles name one grantee")]
    DuplicateGrantee,
    /// A handle's directory is no longer private and owner-bound, or another
    /// grantee claims it.
    #[error("a recipient custody directory is not private, owner-bound and claimed")]
    InvalidDirectory,
    /// Custody is attached once, at composition.
    #[error("recipient custody is already attached")]
    AlreadyAttached,
    /// The store refused the attach transaction: a read-only handle, an
    /// unreadable read-only state, an open outer transaction, or a failed
    /// begin or commit.
    #[error("the store cannot record recipient custody")]
    Unwritable,
}

/// The columns of one withdrawal row that T1, the owner step and T3 read.
struct WithdrawalRowV1 {
    owner_id: String,
    timeline_id: String,
    ciphertext_length: i64,
    ciphertext_digest: Vec<u8>,
    directory_identity: Option<Vec<u8>>,
    final_identity: Option<Vec<u8>>,
    staging_identity: Option<Vec<u8>>,
    capture_status: u8,
    objects_deleted: bool,
    disposition: Option<Vec<u8>>,
}

/// The catalog binding T1 captures against.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CaptureSubjectV1 {
    timeline_id: String,
    ciphertext_length: u64,
    ciphertext_digest: Hash,
}

/// What T1 does for one export.
#[derive(Clone, Debug, Eq, PartialEq)]
enum RetractionV1 {
    /// A captured or withdrawn row, returned unchanged.
    Settled(RecipientExportWithdrawalStateV1),
    /// A publication to retract, or a retracted row to capture again.
    Capture(CaptureSubjectV1),
}

/// One name beneath a custody directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryV1 {
    Absent,
    Unsafe,
    Safe(RecipientPrivateFileIdentityV1),
}

/// The result of one capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureV1 {
    status: u8,
    directory_identity: Option<[u8; 16]>,
    final_identity: Option<RecipientPrivateFileIdentityV1>,
    staging_identity: Option<RecipientPrivateFileIdentityV1>,
}

impl CaptureV1 {
    const fn failed(status: u8) -> Self {
        Self {
            status,
            directory_identity: None,
            final_identity: None,
            staging_identity: None,
        }
    }
}

/// The captured objects of one retracted row and the attached handle of
/// their directory.
struct CapturedObjectsV1<'a> {
    owner: &'a RecipientKeyOwnerV1,
    final_identity: RecipientPrivateFileIdentityV1,
    ciphertext_length: u64,
    staging_identity: Option<RecipientPrivateFileIdentityV1>,
}

#[cfg(test)]
thread_local! {
    static WITHDRAWAL_READONLY_FAILURE: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WITHDRAWAL_BEFORE_RECORD: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static WITHDRAWAL_OBSERVED_SYNCHRONOUS: std::cell::RefCell<Vec<i64>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn withdrawal_is_readonly(connection: &Connection) -> rusqlite::Result<bool> {
    if WITHDRAWAL_READONLY_FAILURE.with(std::cell::Cell::get) {
        Err(rusqlite::Error::InvalidQuery)
    } else {
        connection.is_readonly("main")
    }
}

#[cfg(not(test))]
fn withdrawal_is_readonly(connection: &Connection) -> rusqlite::Result<bool> {
    connection.is_readonly("main")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn observe_withdrawal_synchronous(connection: &Connection) {
    let level = super::current_sqlite_synchronous_level(connection).unwrap_or(-1);
    WITHDRAWAL_OBSERVED_SYNCHRONOUS.with(|observed| observed.borrow_mut().push(level));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn run_before_record_hook() {
    if let Some(hook) = WITHDRAWAL_BEFORE_RECORD.with(std::cell::RefCell::take) {
        hook();
    }
}

impl SqliteStore {
    /// Attach recipient custody once, at composition, before the store is
    /// moved into the erasure host (ADR-138 §4).
    ///
    /// Every handle is validated and its directory claimed for its grantee in
    /// one transaction. Changing custody later means re-composing the store.
    /// Each withdrawal step re-validates the handle it uses, so a directory
    /// that stops being private after attach fails at use.
    ///
    /// # Errors
    ///
    /// Returns [`RecipientCustodyAttachErrorV1::AlreadyAttached`] for a second
    /// call, [`RecipientCustodyAttachErrorV1::DuplicateGrantee`] when two
    /// handles name one grantee, and
    /// [`RecipientCustodyAttachErrorV1::InvalidDirectory`] when a handle fails
    /// its directory validation or claim, and
    /// [`RecipientCustodyAttachErrorV1::Unwritable`] when the store refuses
    /// the claim transaction. Nothing is attached on error.
    pub fn attach_recipient_custody(
        &mut self,
        owners: Vec<RecipientKeyOwnerV1>,
    ) -> Result<(), RecipientCustodyAttachErrorV1> {
        if self.recipient_custody.is_some() {
            return Err(RecipientCustodyAttachErrorV1::AlreadyAttached);
        }
        let grantees = owners
            .iter()
            .map(|owner| owner.grantee_id)
            .collect::<BTreeSet<EntityId>>()
            .len();
        if grantees != owners.len() {
            return Err(RecipientCustodyAttachErrorV1::DuplicateGrantee);
        }
        self.claim_recipient_custody(&owners)
            .map(|()| self.recipient_custody = Some(owners))
    }

    /// Validate and claim every handle in one transaction on a writable,
    /// autocommit `self.conn`; a failed claim rolls the transaction back.
    fn claim_recipient_custody(
        &self,
        owners: &[RecipientKeyOwnerV1],
    ) -> Result<(), RecipientCustodyAttachErrorV1> {
        writable(&self.conn)
            .then_some(())
            .ok_or(RecipientCustodyAttachErrorV1::Unwritable)
            .and_then(|()| {
                self.conn
                    .execute_batch(begin_immediate_sql())
                    .map_err(|_| RecipientCustodyAttachErrorV1::Unwritable)
            })
            .and_then(|()| {
                let rollback = SqliteRollbackOnDrop(&self.conn);
                let claimed = ensure_recipient_custody_tables(&self.conn)
                    .and_then(|()| {
                        owners.iter().try_for_each(|owner| {
                            validate_owner_directory(owner)
                                .and_then(|()| claim_recipient_custody_directory(&self.conn, owner))
                        })
                    })
                    .map_err(|_| RecipientCustodyAttachErrorV1::InvalidDirectory)
                    .and_then(|()| {
                        self.conn
                            .execute_batch("COMMIT")
                            .map_err(|_| RecipientCustodyAttachErrorV1::Unwritable)
                    });
                drop(rollback);
                claimed
            })
    }

    /// ADR-138 T1: retract one publication and capture its objects.
    pub(in crate::sqlite) fn retract_recipient_export(
        &self,
        export_id: [u8; 16],
        grantee_owner: &OwnerIdV1,
    ) -> Result<RecipientExportWithdrawalStateV1, ErasureErrorV1> {
        self.with_withdrawal_durability(ErasureErrorV1::ReceiptCommitFailed, || {
            classify_retraction(&self.conn, export_id, grantee_owner).and_then(|retraction| {
                match retraction {
                    RetractionV1::Settled(state) => Ok(state),
                    RetractionV1::Capture(subject) => {
                        let capture =
                            self.capture_recipient_export(export_id, grantee_owner, &subject);
                        #[cfg(test)]
                        run_before_record_hook();
                        self.record_capture(export_id, grantee_owner, &subject, capture)
                    }
                }
            })
        })
    }

    /// The ADR-138 owner step and T2: unlink the captured objects, sync their
    /// directory and record the deletion, then return the captured binding
    /// the ELXW1 of this withdrawal carries. A row whose binding does not
    /// parse is refused before anything is unlinked.
    ///
    /// Once T2 has committed, the owner step's file work is done: a repeat
    /// returns the recorded binding without custody, re-validation or any
    /// unlink, so a crash after T2 completes on a host restarted without
    /// the captured directory.
    pub(in crate::sqlite) fn delete_captured_recipient_export(
        &self,
        export_id: [u8; 16],
    ) -> Result<RecipientExportWithdrawalBindingV1, ErasureErrorV1> {
        self.with_withdrawal_durability(ErasureErrorV1::ArtifactDeletionFailed, || {
            load_withdrawal_row(&self.conn, export_id)
                .and_then(|row| row.ok_or(ErasureErrorV1::ArtifactDeletionFailed))
                .and_then(|row| {
                    if row.objects_deleted && row.disposition.is_none() {
                        row_binding(export_id, &row).ok_or(ErasureErrorV1::ArtifactDeletionFailed)
                    } else {
                        self.unlink_and_record(export_id, row)
                    }
                })
        })
        .map_err(|_| ErasureErrorV1::ArtifactDeletionFailed)
    }

    /// Unlink the captured objects of a retracted, captured `row` through
    /// its attached, re-validated custody, sync their directory, and commit
    /// T2.
    fn unlink_and_record(
        &self,
        export_id: [u8; 16],
        row: WithdrawalRowV1,
    ) -> Result<RecipientExportWithdrawalBindingV1, ErasureErrorV1> {
        row_binding(export_id, &row)
            .zip(self.captured_objects(row))
            .ok_or(ErasureErrorV1::ArtifactDeletionFailed)
            .and_then(|(binding, captured)| {
                unlink_captured_objects(&captured, export_id)
                    .map(|()| binding)
                    .map_err(|_| ErasureErrorV1::ArtifactDeletionFailed)
            })
            .and_then(|binding| {
                in_immediate_transaction(&self.conn, || {
                    self.conn
                        .execute(
                            "UPDATE recipient_export_withdrawals_v1 SET objects_deleted = 1
                             WHERE export_id = ?1",
                            params![export_id.as_slice()],
                        )
                        .map(|_| binding)
                        .map_err(map_erasure_receipt_failure)
                })
            })
    }

    /// ADR-138 T3: commit the ELXW1 disposition and its ELO1.
    ///
    /// The first commit requires a retracted, captured row whose objects are
    /// deleted and whose fields equal the ELXW1's; it deletes the catalog row
    /// and records the disposition. A withdrawn row accepts only its recorded
    /// ELXW1 and commits just the new ELO1.
    pub(in crate::sqlite) fn commit_recipient_export_withdrawal(
        &self,
        prepared: &PreparedLocalOwnerEffectV1,
        binding: &RecipientExportWithdrawalBindingV1,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        let disposition = prepared
            .effect_object()
            .map(ErasureRetainedObjectV1::reference);
        self.with_withdrawal_durability(ErasureErrorV1::ReceiptCommitFailed, || {
            in_immediate_transaction(&self.conn, || {
                load_withdrawal_row(&self.conn, binding.export_id)
                    .and_then(|row| row.ok_or(ErasureErrorV1::ProvenanceMissing))
                    .and_then(|row| {
                        row.disposition.as_deref().map_or_else(
                            || first_withdrawal(&self.conn, &row, binding, prepared),
                            |recorded| {
                                disposition
                                    .is_some_and(|disposition| {
                                        disposition.digest().as_slice() == recorded
                                    })
                                    .then_some(())
                                    .ok_or(ErasureErrorV1::ProvenanceMissing)
                            },
                        )
                    })
                    .and_then(|()| insert_retained(&self.conn, prepared.owner_result()))
            })
        })
    }

    /// Run one withdrawal step on `self.conn` under `synchronous=FULL`,
    /// refusing a read-only handle, an `is_readonly` error and an open outer
    /// transaction with `refusal`, then restore the previous level. A failed
    /// restore keeps FULL and never reclassifies the step.
    fn with_withdrawal_durability<T>(
        &self,
        refusal: ErasureErrorV1,
        step: impl FnOnce() -> Result<T, ErasureErrorV1>,
    ) -> Result<T, ErasureErrorV1> {
        writable(&self.conn)
            .then_some(())
            .ok_or(refusal)
            .and_then(|()| ensure_recipient_export_durability(&self.conn).map_err(|_| refusal))
            .and_then(|previous| {
                let result = step();
                drop(restore_recipient_export_synchronous_level(
                    &self.conn, previous,
                ));
                result
            })
    }

    /// The attached handle of the grantee whose recipient owner is
    /// `owner_id`, of the recorded `directory` when one is given, that is
    /// still private, owner-bound and claimed. Attach admits one handle per
    /// grantee.
    fn usable_custody(
        &self,
        owner_id: &str,
        directory: Option<&[u8]>,
    ) -> Option<&RecipientKeyOwnerV1> {
        self.recipient_custody.iter().flatten().find(|owner| {
            recipient_owner_id_from_grantee(owner.grantee_id)
                .is_ok_and(|candidate| candidate.as_str() == owner_id)
                && directory.is_none_or(|directory| directory_identity(owner) == directory)
                && custody_usable(&self.conn, owner)
        })
    }

    /// Capture the objects of one publication in its grantee's attached,
    /// re-validated directory (ADR-138 §5, capture).
    fn capture_recipient_export(
        &self,
        export_id: [u8; 16],
        grantee_owner: &OwnerIdV1,
        subject: &CaptureSubjectV1,
    ) -> CaptureV1 {
        self.usable_custody(grantee_owner.as_str(), None)
            .map_or_else(
                || CaptureV1::failed(NO_CUSTODY),
                |owner| capture_objects(owner, export_id, subject),
            )
    }

    /// Record one capture in a durable transaction, after re-checking that
    /// the export still needs it and that the captured final name still
    /// holds the captured object.
    fn record_capture(
        &self,
        export_id: [u8; 16],
        grantee_owner: &OwnerIdV1,
        subject: &CaptureSubjectV1,
        capture: CaptureV1,
    ) -> Result<RecipientExportWithdrawalStateV1, ErasureErrorV1> {
        local_erasure_export_recipient_v1(export_id, grantee_owner).and_then(|target| {
            in_immediate_transaction(&self.conn, || {
                classify_retraction(&self.conn, export_id, grantee_owner).and_then(|now| {
                    if now != RetractionV1::Capture(subject.clone()) {
                        return Err(ErasureErrorV1::ReceiptCommitFailed);
                    }
                    let capture = self.confirm_capture(export_id, grantee_owner, capture);
                    upsert_capture(
                        &self.conn,
                        export_id,
                        target,
                        grantee_owner,
                        subject,
                        capture,
                    )
                    .map(|()| RecipientExportWithdrawalStateV1::Retracted {
                        capture_status: capture.status,
                        objects_deleted: false,
                    })
                })
            })
        })
    }

    /// Re-check a capture inside its transaction: custody that is no longer
    /// usable is no custody, and a captured final name that no longer holds
    /// the captured object is unsafe.
    fn confirm_capture(
        &self,
        export_id: [u8; 16],
        grantee_owner: &OwnerIdV1,
        capture: CaptureV1,
    ) -> CaptureV1 {
        capture.final_identity.map_or(capture, |captured| {
            self.usable_custody(
                grantee_owner.as_str(),
                capture
                    .directory_identity
                    .as_ref()
                    .map(<[u8; 16]>::as_slice),
            )
            .map_or_else(
                || CaptureV1::failed(NO_CUSTODY),
                |owner| {
                    if stat_entry(owner, &recipient_export_final_name(export_id))
                        == EntryV1::Safe(captured)
                    {
                        capture
                    } else {
                        CaptureV1::failed(UNSAFE)
                    }
                },
            )
        })
    }

    /// The captured objects of a retracted, captured row and the attached,
    /// re-validated handle of their recorded directory.
    fn captured_objects(&self, row: WithdrawalRowV1) -> Option<CapturedObjectsV1<'_>> {
        let staging_identity = row
            .staging_identity
            .as_deref()
            .map_or(Some(None), |bytes| file_identity(bytes).map(Some));
        (row.disposition.is_none() && row.capture_status == CAPTURED)
            .then_some(())
            .and_then(|()| {
                row.directory_identity
                    .zip(row.final_identity.as_deref().and_then(file_identity))
                    .zip(staging_identity)
                    .zip(u64::try_from(row.ciphertext_length).ok())
            })
            .and_then(
                |(((directory, final_identity), staging_identity), ciphertext_length)| {
                    self.usable_custody(&row.owner_id, Some(directory.as_slice()))
                        .map(|owner| CapturedObjectsV1 {
                            owner,
                            final_identity,
                            ciphertext_length,
                            staging_identity,
                        })
                },
            )
    }
}

/// Run `work` in one `BEGIN IMMEDIATE` transaction on `connection`; a commit
/// or rollback failure is [`ErasureErrorV1::ReceiptCommitFailed`].
fn in_immediate_transaction<T>(
    connection: &Connection,
    work: impl FnOnce() -> Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1> {
    connection
        .execute_batch(begin_immediate_sql())
        .map_err(map_erasure_receipt_failure)
        .and_then(|()| {
            #[cfg(test)]
            observe_withdrawal_synchronous(connection);
            finish_erasure_transaction(connection, work())
        })
}

/// Whether `connection` may begin a durable write: autocommit, and known
/// not to be read-only (an `is_readonly` error is a refusal).
fn writable(connection: &Connection) -> bool {
    connection.is_autocommit() && withdrawal_is_readonly(connection).ok() == Some(false)
}

/// Whether a handle is still private, owner-bound and claimed for its
/// grantee.
fn custody_usable(connection: &Connection, owner: &RecipientKeyOwnerV1) -> bool {
    validate_owner_directory(owner)
        .and_then(|()| claim_recipient_custody_directory(connection, owner))
        .is_ok()
}

/// The withdrawal row of `export_id`; a store without the withdrawal table
/// never published, so it has none.
fn load_withdrawal_row(
    connection: &Connection,
    export_id: [u8; 16],
) -> Result<Option<WithdrawalRowV1>, ErasureErrorV1> {
    table_present(connection, RECIPIENT_EXPORT_WITHDRAWALS).and_then(|present| {
        if !present {
            return Ok(None);
        }
        connection
            .query_row(
                "SELECT owner_id, timeline_id, ciphertext_length, ciphertext_digest,
                        directory_identity, final_identity, staging_identity, capture_status,
                        objects_deleted, disposition
                 FROM recipient_export_withdrawals_v1 WHERE export_id = ?1",
                params![export_id.as_slice()],
                |row| {
                    Ok(WithdrawalRowV1 {
                        owner_id: row.get(0)?,
                        timeline_id: row.get(1)?,
                        ciphertext_length: row.get(2)?,
                        ciphertext_digest: row.get(3)?,
                        directory_identity: row.get(4)?,
                        final_identity: row.get(5)?,
                        staging_identity: row.get(6)?,
                        capture_status: row.get(7)?,
                        objects_deleted: row.get(8)?,
                        disposition: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(map_erasure_receipt_failure)
    })
}

/// Decide T1 for one export: an unknown export, or one of another owner, is
/// [`ErasureErrorV1::ProvenanceMissing`].
fn classify_retraction(
    connection: &Connection,
    export_id: [u8; 16],
    grantee_owner: &OwnerIdV1,
) -> Result<RetractionV1, ErasureErrorV1> {
    load_withdrawal_row(connection, export_id).and_then(|row| {
        row.map_or_else(
            || classify_catalog_row(connection, export_id, grantee_owner),
            |row| classify_withdrawal_row(connection, row, grantee_owner),
        )
    })
}

/// T1 for an export without a withdrawal row: retract its catalog row.
fn classify_catalog_row(
    connection: &Connection,
    export_id: [u8; 16],
    grantee_owner: &OwnerIdV1,
) -> Result<RetractionV1, ErasureErrorV1> {
    load_recipient_export_catalog(connection, export_id)
        .map_err(|_| ErasureErrorV1::ReceiptCommitFailed)
        .and_then(|catalog| {
            catalog
                .filter(|catalog| catalog.owner_id == grantee_owner.as_str())
                .ok_or(ErasureErrorV1::ProvenanceMissing)
        })
        .and_then(|catalog| {
            capture_subject(
                catalog.timeline_id,
                u64::try_from(catalog.ciphertext_length).ok(),
                &catalog.ciphertext_digest,
            )
        })
        .map(RetractionV1::Capture)
}

fn classify_withdrawal_row(
    connection: &Connection,
    row: WithdrawalRowV1,
    grantee_owner: &OwnerIdV1,
) -> Result<RetractionV1, ErasureErrorV1> {
    if row.owner_id != grantee_owner.as_str() {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    match (row.disposition, row.capture_status) {
        (Some(disposition), _) => reference_from_sql(disposition).and_then(|disposition| {
            load_sqlite_erasure_evidence(connection, disposition).map(|elxw1| {
                RetractionV1::Settled(RecipientExportWithdrawalStateV1::Withdrawn {
                    disposition,
                    elxw1,
                })
            })
        }),
        (None, CAPTURED) => Ok(RetractionV1::Settled(
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: CAPTURED,
                objects_deleted: row.objects_deleted,
            },
        )),
        (None, _) => capture_subject(
            row.timeline_id,
            u64::try_from(row.ciphertext_length).ok(),
            &row.ciphertext_digest,
        )
        .map(RetractionV1::Capture),
    }
}

/// The catalog binding of one export; a malformed length or digest is
/// [`ErasureErrorV1::ProvenanceMissing`].
fn capture_subject(
    timeline_id: String,
    ciphertext_length: Option<u64>,
    ciphertext_digest: &[u8],
) -> Result<CaptureSubjectV1, ErasureErrorV1> {
    ciphertext_length
        .zip(<[u8; 32]>::try_from(ciphertext_digest).ok())
        .map(|(ciphertext_length, digest)| CaptureSubjectV1 {
            timeline_id,
            ciphertext_length,
            ciphertext_digest: Hash::from_bytes(digest),
        })
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

/// Capture the final and staging objects of one export beneath `owner`.
fn capture_objects(
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
    subject: &CaptureSubjectV1,
) -> CaptureV1 {
    let staging = stat_entry(owner, &recipient_export_staging_name(export_id));
    match (capture_final(owner, export_id, subject), staging) {
        (EntryV1::Unsafe, _) | (_, EntryV1::Unsafe) => CaptureV1::failed(UNSAFE),
        (EntryV1::Absent, _) => CaptureV1::failed(FINAL_MISSING),
        (EntryV1::Safe(final_identity), staging) => CaptureV1 {
            status: CAPTURED,
            directory_identity: Some(directory_identity(owner)),
            final_identity: Some(final_identity),
            staging_identity: match staging {
                EntryV1::Safe(identity) => Some(identity),
                _ => None,
            },
        },
    }
}

/// Open the final name read-only beneath the directory, require a private
/// single-link file of the catalog's exact length whose BLAKE3 over the
/// descriptor is the catalog digest, then require the name to still hold
/// that file.
fn capture_final(
    owner: &RecipientKeyOwnerV1,
    export_id: [u8; 16],
    subject: &CaptureSubjectV1,
) -> EntryV1 {
    let name = recipient_export_final_name(export_id);
    let opened = recipient_openat2(
        &owner.directory_file,
        name.as_slice(),
        OBJECT_OPEN,
        Mode::empty(),
        OBJECT_RESOLVE,
    );
    match opened {
        Err(rustix::io::Errno::NOENT) => EntryV1::Absent,
        opened => opened
            .ok()
            .map(File::from)
            .and_then(|file| {
                file.metadata()
                    .ok()
                    .filter(|metadata| {
                        validate_recipient_export_file(metadata, owner, subject.ciphertext_length)
                            .is_ok()
                            && digest_matches(&file, subject)
                    })
                    .map(|metadata| RecipientPrivateFileIdentityV1::from_metadata(&metadata))
            })
            .filter(|opened| stat_entry(owner, &name) == EntryV1::Safe(*opened))
            .map_or(EntryV1::Unsafe, EntryV1::Safe),
    }
}

/// Whether streaming BLAKE3 over `file` reads exactly the catalog length and
/// yields the catalog digest.
fn digest_matches(file: &File, subject: &CaptureSubjectV1) -> bool {
    let mut hasher = blake3::Hasher::new();
    let copied = std::io::copy(
        &mut file.take(subject.ciphertext_length.saturating_add(1)),
        &mut hasher,
    )
    .ok();
    copied == Some(subject.ciphertext_length)
        && hasher.finalize().as_bytes() == subject.ciphertext_digest.as_bytes()
}

/// The entry at `name` beneath `owner`'s directory, without following a
/// symbolic link.
fn stat_entry(owner: &RecipientKeyOwnerV1, name: &[u8]) -> EntryV1 {
    match recipient_statat(&owner.directory_file, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) if is_safe_recipient_export_entry(owner, &stat) => {
            EntryV1::Safe(RecipientPrivateFileIdentityV1 {
                device: stat.st_dev.to_be_bytes(),
                inode: stat.st_ino.to_be_bytes(),
                uid: stat.st_uid.to_be_bytes(),
            })
        }
        Err(rustix::io::Errno::NOENT) => EntryV1::Absent,
        _ => EntryV1::Unsafe,
    }
}

/// Unlink every captured name that still holds its captured object, then
/// sync the directory. An absent captured name was unlinked by an earlier
/// attempt (ADR-138 §5).
fn unlink_captured_objects(
    captured: &CapturedObjectsV1<'_>,
    export_id: [u8; 16],
) -> Result<(), CoreError> {
    unlink_captured(
        captured.owner,
        &recipient_export_final_name(export_id),
        captured.final_identity,
        Some(captured.ciphertext_length),
    )
    .and_then(|()| {
        captured.staging_identity.map_or(Ok(()), |identity| {
            unlink_captured(
                captured.owner,
                &recipient_export_staging_name(export_id),
                identity,
                None,
            )
        })
    })
    .and_then(|()| recipient_fsync(&captured.owner.directory_file).map_err(storage_error))
}

/// Open `name` beneath the directory, require the captured `(dev, inode,
/// uid)`, one link and, for the final name, the exact length, require the
/// name to still hold that file, then unlink it.
///
/// An absent captured name reads as already deleted (ADR-138 §5): the crash
/// case after an earlier unlink. A captured name renamed away out of band
/// therefore also reads as deleted, the same trade-off as key destruction's
/// absent-name rule; the custody directory is owner-private.
fn unlink_captured(
    owner: &RecipientKeyOwnerV1,
    name: &[u8],
    expected: RecipientPrivateFileIdentityV1,
    length: Option<u64>,
) -> Result<(), CoreError> {
    let opened = recipient_openat2(
        &owner.directory_file,
        name,
        OBJECT_OPEN,
        Mode::empty(),
        OBJECT_RESOLVE,
    );
    match opened {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        opened => opened
            .map(File::from)
            .map_err(storage_error)
            .and_then(|file| file.metadata().map_err(storage_error))
            .and_then(|metadata| {
                // A safe name entry has one link, so the descriptor and the
                // name holding the captured object fix its link count.
                let opened = RecipientPrivateFileIdentityV1::from_metadata(&metadata);
                if (opened, stat_entry(owner, name)) == (expected, EntryV1::Safe(expected))
                    && length.is_none_or(|length| metadata.len() == length)
                {
                    recipient_unlinkat(&owner.directory_file, name, AtFlags::empty())
                        .map_err(storage_error)
                } else {
                    Err(CoreError::Storage(
                        "recipient export object differs from its captured identity".to_owned(),
                    ))
                }
            }),
    }
}

/// Insert or re-capture one retracted row.
fn upsert_capture(
    connection: &Connection,
    export_id: [u8; 16],
    target: ErasureReferenceV1,
    grantee_owner: &OwnerIdV1,
    subject: &CaptureSubjectV1,
    capture: CaptureV1,
) -> Result<(), ErasureErrorV1> {
    connection
        .execute(
            "INSERT INTO recipient_export_withdrawals_v1
             (export_id, target, owner_id, timeline_id, ciphertext_length, ciphertext_digest,
              directory_identity, final_identity, staging_identity, capture_status,
              objects_deleted, disposition, committed_elo1)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, NULL, NULL)
             ON CONFLICT (export_id) DO UPDATE SET
               directory_identity = excluded.directory_identity,
               final_identity = excluded.final_identity,
               staging_identity = excluded.staging_identity,
               capture_status = excluded.capture_status",
            params![
                export_id.as_slice(),
                target.digest().as_slice(),
                grantee_owner.as_str(),
                subject.timeline_id,
                // Always `Some`: the length was read from an INTEGER column.
                i64::try_from(subject.ciphertext_length).ok(),
                subject.ciphertext_digest.as_bytes().as_slice(),
                capture.directory_identity.map(Vec::from),
                capture.final_identity.map(file_identity_bytes),
                capture.staging_identity.map(file_identity_bytes),
                capture.status,
            ],
        )
        .map(drop)
        .map_err(map_erasure_receipt_failure)
}

/// The first T3 of one export: the row and the ELXW1 must agree, then the
/// catalog row is deleted and the disposition recorded with the ELXW1.
fn first_withdrawal(
    connection: &Connection,
    row: &WithdrawalRowV1,
    binding: &RecipientExportWithdrawalBindingV1,
    prepared: &PreparedLocalOwnerEffectV1,
) -> Result<(), ErasureErrorV1> {
    let agrees = row.objects_deleted
        && row.capture_status == CAPTURED
        && row.owner_id == binding.grantee_owner.as_str()
        && u64::try_from(row.ciphertext_length).ok() == Some(binding.ciphertext_length)
        && row.ciphertext_digest.as_slice() == binding.ciphertext_digest.as_bytes()
        && row.directory_identity.as_deref() == Some(binding.directory_identity.as_slice())
        && row.final_identity.as_deref() == Some(binding.final_identity.as_slice())
        && parse_timeline_id(&row.timeline_id)
            .is_ok_and(|timeline| timeline == binding.timeline_id);
    if !agrees {
        return Err(ErasureErrorV1::ProvenanceMissing);
    }
    connection
        .execute(
            "DELETE FROM recipient_export_catalog_v1 WHERE export_id = ?1",
            params![binding.export_id.as_slice()],
        )
        .and_then(|_| {
            connection.execute(
                "UPDATE recipient_export_withdrawals_v1 SET disposition = ?2, committed_elo1 = ?3
                 WHERE export_id = ?1",
                params![
                    binding.export_id.as_slice(),
                    prepared
                        .effect_object()
                        .map(|object| object.reference().digest().to_vec()),
                    prepared.owner_result().reference().digest().as_slice(),
                ],
            )
        })
        .map_err(map_erasure_receipt_failure)
        .and_then(|_| {
            prepared.effect_object().map_or(Ok(()), |object| {
                insert_retained(connection, object).map(drop)
            })
        })
}

/// The ELXW1 binding of a captured withdrawal row: its grantee, source
/// Timeline, catalog length and digest, and captured directory and final
/// identities. `None` for a row any of whose fields does not parse.
fn row_binding(
    export_id: [u8; 16],
    row: &WithdrawalRowV1,
) -> Option<RecipientExportWithdrawalBindingV1> {
    OwnerIdV1::new(row.owner_id.as_str())
        .ok()
        .zip(parse_timeline_id(&row.timeline_id).ok())
        .zip(<[u8; 32]>::try_from(row.ciphertext_digest.as_slice()).ok())
        .zip(
            row.directory_identity
                .as_deref()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok()),
        )
        .zip(
            row.final_identity
                .as_deref()
                .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok()),
        )
        .zip(u64::try_from(row.ciphertext_length).ok())
        .map(
            |(
                ((((grantee_owner, timeline_id), digest), directory_identity), final_identity),
                ciphertext_length,
            )| RecipientExportWithdrawalBindingV1 {
                export_id,
                timeline_id,
                grantee_owner,
                ciphertext_digest: Hash::from_bytes(digest),
                ciphertext_length,
                directory_identity,
                final_identity,
            },
        )
}

/// A custody directory's big-endian `(device, inode)`.
fn directory_identity(owner: &RecipientKeyOwnerV1) -> [u8; 16] {
    let mut identity = [0; 16];
    identity[..8].copy_from_slice(&owner.directory_identity.device);
    identity[8..].copy_from_slice(&owner.directory_identity.inode);
    identity
}

/// A file's big-endian `(device, inode, uid)`.
fn file_identity_bytes(identity: RecipientPrivateFileIdentityV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&identity.device);
    bytes.extend_from_slice(&identity.inode);
    bytes.extend_from_slice(&identity.uid);
    bytes
}

/// Decode a recorded `(device, inode, uid)`.
fn file_identity(bytes: &[u8]) -> Option<RecipientPrivateFileIdentityV1> {
    <[u8; 20]>::try_from(bytes).ok().map(|bytes| {
        let (device, rest) = bytes.split_at(8);
        let (inode, uid) = rest.split_at(8);
        RecipientPrivateFileIdentityV1 {
            device: device.try_into().unwrap_or_default(),
            inode: inode.try_into().unwrap_or_default(),
            uid: uid.try_into().unwrap_or_default(),
        }
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        ErasureInventoryPersistencePortV1, LocalErasureRecipientExportWithdrawalV1,
        LocalOwnerEffectV1, LocalOwnerResultBindingV1, TimelineId,
    };

    use super::super::tests::{
        recipient_publication_fixture, recipient_publication_request, RecipientPublicationFixture,
        RecipientTestResult,
    };
    use super::super::{
        current_sqlite_synchronous_level, RecipientExportPublicationErrorV1,
        RECIPIENT_DURABILITY_SYNCHRONOUS_OVERRIDE, RECIPIENT_FSYNC_CALLS, RECIPIENT_FSYNC_FAILURE,
        RECIPIENT_RANDOM_OVERRIDE, RECIPIENT_UNLINK_FAILURE,
    };
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// One publication of the fixture's grantee, with a second handle on its
    /// directory attached as custody.
    fn published() -> RecipientTestResult<(RecipientPublicationFixture, [u8; 16])> {
        let mut fixture = recipient_publication_fixture()?;
        let request = recipient_publication_request(
            fixture.timeline,
            fixture.descriptor,
            &fixture.evaluation,
            &fixture.token,
        );
        let export_id = fixture
            .store
            .publish_recipient_export(&fixture.authority, &fixture.owner, &request)?
            .export_id;
        let custody =
            RecipientKeyOwnerV1::open(fixture.owner.directory.clone(), fixture.owner.grantee_id)?;
        fixture.store.attach_recipient_custody(vec![custody])?;
        Ok((fixture, export_id))
    }

    /// The ELXW1 of the recorded row of `export_id`.
    fn recorded_elxw1(
        store: &SqliteStore,
        export_id: [u8; 16],
        timeline: TimelineId,
    ) -> RecipientTestResult<Vec<u8>> {
        let (owner, length, digest, directory, final_identity): (
            String,
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = store.conn.query_row(
            "SELECT owner_id, ciphertext_length, ciphertext_digest, directory_identity,
                    final_identity
             FROM recipient_export_withdrawals_v1 WHERE export_id = ?1",
            params![export_id.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        Ok(LocalErasureRecipientExportWithdrawalV1 {
            request: ErasureReferenceV1::from_digest([1; 32]),
            command: ErasureReferenceV1::from_digest([5; 32]),
            export_id,
            timeline_id: timeline,
            grantee_owner: OwnerIdV1::new(owner)?,
            ciphertext_digest: Hash::from_bytes(digest.as_slice().try_into()?),
            ciphertext_length: u64::try_from(length)?,
            directory_identity: directory.as_slice().try_into()?,
            final_identity: final_identity.as_slice().try_into()?,
        }
        .to_canonical_cbor()?)
    }

    fn prepared(elxw1: Vec<u8>) -> Result<PreparedLocalOwnerEffectV1, ErasureErrorV1> {
        PreparedLocalOwnerEffectV1::new(
            LocalOwnerEffectV1::RecipientExportWithdrawal(elxw1),
            LocalOwnerResultBindingV1 {
                request: ErasureReferenceV1::from_digest([1; 32]),
                attempt: ErasureReferenceV1::from_digest([2; 32]),
                obligation: ErasureReferenceV1::from_digest([3; 32]),
                command: ErasureReferenceV1::from_digest([5; 32]),
                owner_ref: ErasureReferenceV1::from_digest([4; 32]),
                error: None,
            },
        )
    }

    /// T1, the owner step and T3 are each refused with their closed code,
    /// with `before` run ahead of each step.
    fn assert_refused(
        store: &mut SqliteStore,
        export_id: [u8; 16],
        grantee: &OwnerIdV1,
        before: &dyn Fn(),
    ) -> RecipientTestResult {
        let elxw1 = LocalErasureRecipientExportWithdrawalV1 {
            request: ErasureReferenceV1::from_digest([1; 32]),
            command: ErasureReferenceV1::from_digest([5; 32]),
            export_id,
            timeline_id: TimelineId::new(),
            grantee_owner: *grantee,
            ciphertext_digest: Hash::from_bytes([6; 32]),
            ciphertext_length: 7,
            directory_identity: [8; 16],
            final_identity: [9; 20],
        }
        .to_canonical_cbor()?;
        before();
        assert_eq!(
            store.begin_recipient_export_withdrawal(export_id, grantee),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        before();
        assert_eq!(
            store.delete_recipient_export_ciphertext(export_id),
            Err(ErasureErrorV1::ArtifactDeletionFailed)
        );
        before();
        assert_eq!(
            store.commit_local_owner_effect(prepared(elxw1)?),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        Ok(())
    }

    #[test]
    fn every_withdrawal_step_commits_under_full_and_restores_the_level() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        fixture
            .store
            .conn
            .execute_batch("PRAGMA synchronous=NORMAL")?;
        let normal = current_sqlite_synchronous_level(&fixture.store.conn)?;
        WITHDRAWAL_OBSERVED_SYNCHRONOUS.with(|observed| observed.borrow_mut().clear());
        let grantee = fixture.descriptor.identity().owner_id;
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: CAPTURED,
                objects_deleted: false,
            }
        );
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            normal
        );
        fixture
            .store
            .delete_recipient_export_ciphertext(export_id)?;
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            normal
        );
        let elxw1 = recorded_elxw1(&fixture.store, export_id, fixture.timeline)?;
        fixture.store.commit_local_owner_effect(prepared(elxw1)?)?;
        assert_eq!(
            current_sqlite_synchronous_level(&fixture.store.conn)?,
            normal
        );
        let observed = WITHDRAWAL_OBSERVED_SYNCHRONOUS.with(std::cell::RefCell::take);
        assert_eq!(observed.len(), 3);
        assert!(observed.iter().all(|level| *level >= 2), "{observed:?}");
        Ok(())
    }

    #[test]
    fn every_withdrawal_step_refuses_an_unwritable_connection() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let grantee = fixture.descriptor.identity().owner_id;
        // An open outer transaction.
        fixture.store.conn.execute_batch("BEGIN")?;
        assert_refused(&mut fixture.store, export_id, &grantee, &|| {})?;
        fixture.store.conn.execute_batch("ROLLBACK")?;
        // An `is_readonly` error.
        WITHDRAWAL_READONLY_FAILURE.with(|failure| failure.set(true));
        let readonly_error = assert_refused(&mut fixture.store, export_id, &grantee, &|| {});
        WITHDRAWAL_READONLY_FAILURE.with(|failure| failure.set(false));
        readonly_error?;
        // A read-back below FULL.
        assert_refused(&mut fixture.store, export_id, &grantee, &|| {
            RECIPIENT_DURABILITY_SYNCHRONOUS_OVERRIDE.with(|level| level.set(Some(1)));
        })?;
        // A read-only handle whose writer reservation connection is absent.
        let path = fixture
            .store
            .conn
            .path()
            .ok_or("database path is unavailable")?
            .to_owned();
        let mut read_only = SqliteStore::open_read_only(&path)?;
        read_only.writer_reservation_connection = None;
        assert_refused(&mut read_only, export_id, &grantee, &|| {})?;
        // Nothing was retracted.
        assert!(load_withdrawal_row(&fixture.store.conn, export_id)?.is_none());
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: CAPTURED,
                objects_deleted: false,
            }
        );
        Ok(())
    }

    #[test]
    fn a_retraction_rechecks_its_catalog_row_inside_its_transaction() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let path = fixture
            .store
            .conn
            .path()
            .ok_or("database path is unavailable")?
            .to_owned();
        WITHDRAWAL_BEFORE_RECORD.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let changed = Connection::open(path).and_then(|connection| {
                    connection.execute(
                        "UPDATE recipient_export_catalog_v1
                         SET ciphertext_length = ciphertext_length + 1",
                        [],
                    )
                });
                assert_eq!(changed.ok(), Some(1));
            }));
        });
        let grantee = fixture.descriptor.identity().owner_id;
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        assert!(load_withdrawal_row(&fixture.store.conn, export_id)?.is_none());
        Ok(())
    }

    /// The replacement is a private single-link file, so only its new
    /// identity differs from the capture.
    #[test]
    fn a_final_object_replaced_before_the_record_is_unsafe() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let final_path = fixture
            .owner
            .directory
            .join(String::from_utf8(recipient_export_final_name(export_id))?);
        WITHDRAWAL_BEFORE_RECORD.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let fresh = final_path.with_extension("replacement");
                let replaced = std::fs::read(&final_path)
                    .and_then(|bytes| std::fs::write(&fresh, bytes))
                    .and_then(|()| {
                        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o600))
                    })
                    .and_then(|()| std::fs::rename(fresh, final_path));
                assert!(replaced.is_ok());
            }));
        });
        let grantee = fixture.descriptor.identity().owner_id;
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: UNSAFE,
                objects_deleted: false,
            }
        );
        Ok(())
    }

    #[test]
    fn the_reservation_refuses_a_withdrawn_export_id() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let grantee = fixture.descriptor.identity().owner_id;
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?;
        fixture
            .store
            .delete_recipient_export_ciphertext(export_id)?;
        let elxw1 = recorded_elxw1(&fixture.store, export_id, fixture.timeline)?;
        fixture.store.commit_local_owner_effect(prepared(elxw1)?)?;
        assert!(load_recipient_export_catalog(&fixture.store.conn, export_id)?.is_none());
        RECIPIENT_RANDOM_OVERRIDE.with(|bytes| *bytes.borrow_mut() = Some(export_id.to_vec()));
        assert!(matches!(
            fixture.store.reserve_recipient_export_id(&fixture.owner),
            Err(RecipientExportPublicationErrorV1::IdentifierCollision)
        ));
        Ok(())
    }

    #[test]
    fn custody_lost_before_the_record_is_no_custody() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let directory = fixture.owner.directory.clone();
        WITHDRAWAL_BEFORE_RECORD.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let changed =
                    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755));
                assert!(changed.is_ok());
            }));
        });
        let grantee = fixture.descriptor.identity().owner_id;
        let state = fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee);
        std::fs::set_permissions(
            &fixture.owner.directory,
            std::fs::Permissions::from_mode(0o700),
        )?;
        assert_eq!(
            state?,
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: NO_CUSTODY,
                objects_deleted: false,
            }
        );
        Ok(())
    }

    #[test]
    fn a_failed_unlink_or_directory_sync_leaves_the_owner_step_negative() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let grantee = fixture.descriptor.identity().owner_id;
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?;
        let final_path = fixture
            .owner
            .directory
            .join(String::from_utf8(recipient_export_final_name(export_id))?);
        RECIPIENT_UNLINK_FAILURE.with(|failure| failure.set(true));
        let unlink = fixture.store.delete_recipient_export_ciphertext(export_id);
        RECIPIENT_UNLINK_FAILURE.with(|failure| failure.set(false));
        assert_eq!(unlink, Err(ErasureErrorV1::ArtifactDeletionFailed));
        assert!(final_path.exists());
        // The directory sync after the unlink fails; a re-run accepts the
        // absent captured name.
        RECIPIENT_FSYNC_CALLS.with(|calls| calls.set(0));
        RECIPIENT_FSYNC_FAILURE.with(|failure| failure.set(Some(0)));
        let sync = fixture.store.delete_recipient_export_ciphertext(export_id);
        RECIPIENT_FSYNC_FAILURE.with(|failure| failure.set(None));
        assert_eq!(sync, Err(ErasureErrorV1::ArtifactDeletionFailed));
        assert!(!final_path.exists());
        assert_eq!(
            fixture
                .store
                .begin_recipient_export_withdrawal(export_id, &grantee)?,
            RecipientExportWithdrawalStateV1::Retracted {
                capture_status: CAPTURED,
                objects_deleted: false,
            }
        );
        fixture
            .store
            .delete_recipient_export_ciphertext(export_id)?;
        Ok(())
    }

    #[test]
    fn a_captured_row_whose_binding_does_not_parse_unlinks_nothing() -> RecipientTestResult {
        let (mut fixture, export_id) = published()?;
        let grantee = fixture.descriptor.identity().owner_id;
        fixture
            .store
            .begin_recipient_export_withdrawal(export_id, &grantee)?;
        let final_path = fixture
            .owner
            .directory
            .join(String::from_utf8(recipient_export_final_name(export_id))?);
        fixture.store.conn.execute_batch(
            "UPDATE recipient_export_withdrawals_v1 SET timeline_id = 'not-a-timeline'",
        )?;
        assert_eq!(
            fixture.store.delete_recipient_export_ciphertext(export_id),
            Err(ErasureErrorV1::ArtifactDeletionFailed)
        );
        assert!(final_path.exists());
        // Restored, the same row deletes and returns the ELXW1 binding of
        // its recorded capture.
        fixture.store.conn.execute(
            "UPDATE recipient_export_withdrawals_v1 SET timeline_id = ?1",
            params![fixture.timeline.to_string()],
        )?;
        let binding = fixture
            .store
            .delete_recipient_export_ciphertext(export_id)?;
        assert!(!final_path.exists());
        // After T2 a repeat unlinks nothing, but still refuses a binding
        // that does not parse.
        fixture.store.conn.execute_batch(
            "UPDATE recipient_export_withdrawals_v1 SET timeline_id = 'not-a-timeline'",
        )?;
        assert_eq!(
            fixture.store.delete_recipient_export_ciphertext(export_id),
            Err(ErasureErrorV1::ArtifactDeletionFailed)
        );
        fixture.store.conn.execute(
            "UPDATE recipient_export_withdrawals_v1 SET timeline_id = ?1",
            params![fixture.timeline.to_string()],
        )?;
        assert_eq!(
            fixture.store.delete_recipient_export_ciphertext(export_id),
            Ok(binding)
        );
        let elxw1 = recorded_elxw1(&fixture.store, export_id, fixture.timeline)?;
        assert_eq!(
            binding,
            RecipientExportWithdrawalBindingV1::from(
                &LocalErasureRecipientExportWithdrawalV1::from_canonical_cbor(&elxw1)?
            )
        );
        Ok(())
    }

    #[test]
    fn attach_refuses_an_unwritable_store_and_attaches_nothing() -> RecipientTestResult {
        let mut fixture = recipient_publication_fixture()?;
        let custody =
            || RecipientKeyOwnerV1::open(fixture.owner.directory.clone(), fixture.owner.grantee_id);
        let handles = [custody()?, custody()?, custody()?, custody()?];
        let [outer, readonly_error, begin, commit] = handles;
        // An open outer transaction.
        fixture.store.conn.execute_batch("BEGIN")?;
        let refused = fixture.store.attach_recipient_custody(vec![outer]);
        fixture.store.conn.execute_batch("ROLLBACK")?;
        assert_eq!(refused, Err(RecipientCustodyAttachErrorV1::Unwritable));
        // An `is_readonly` error.
        WITHDRAWAL_READONLY_FAILURE.with(|failure| failure.set(true));
        let refused = fixture.store.attach_recipient_custody(vec![readonly_error]);
        WITHDRAWAL_READONLY_FAILURE.with(|failure| failure.set(false));
        assert_eq!(refused, Err(RecipientCustodyAttachErrorV1::Unwritable));
        // A failed begin.
        crate::sqlite::FAIL_BEGIN_IMMEDIATE.with(|failure| failure.set(true));
        let refused = fixture.store.attach_recipient_custody(vec![begin]);
        crate::sqlite::FAIL_BEGIN_IMMEDIATE.with(|failure| failure.set(false));
        assert_eq!(refused, Err(RecipientCustodyAttachErrorV1::Unwritable));
        // A failed commit.
        fixture.store.conn.commit_hook(Some(|| true))?;
        let refused = fixture.store.attach_recipient_custody(vec![commit]);
        fixture.store.conn.commit_hook::<fn() -> bool>(None)?;
        assert_eq!(refused, Err(RecipientCustodyAttachErrorV1::Unwritable));
        assert!(fixture.store.conn.is_autocommit());
        // Nothing was attached.
        fixture.store.attach_recipient_custody(vec![custody()?])?;
        Ok(())
    }
}
