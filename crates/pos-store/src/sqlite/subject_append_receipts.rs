#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-137 A1-A2 subject-data append receipts and the owner append-MAC key.
//!
//! A subject-data append has no durable intent (A1). Exactly-once comes from
//! one receipt row in `subject_data_append_receipts`, written in the same
//! commit as the Event, and from the predecessor check (A3). This module owns
//! the table, the request digest, the receipt lookup, insert and purge, and
//! the custody of the owner append-MAC key file `subject-append-mac.v1.key`.
//!
//! The gate order of the combined append (A5), the predecessor check (A3) and
//! the owner write API that calls these functions are other slices. Gate 1,
//! the `OwnerConsentV2PermitV1` binding, is already the store's
//! `bind_owner_consent_v2_permit`. Everything here stays test-support gated
//! until owner activation (#1438).
//!
//! Only a writable open creates and validates the table. A read-only open
//! neither creates nor validates it: when the table is absent a lookup
//! answers [`SubjectAppendReceiptRefusalV1::Unreadable`], but when the table
//! exists a lookup answers from it without validating its shape. The
//! qualified owner constructor (#1438) must validate the table shape itself, and ungating in
//! #1438 must remove both `cfg` gates (this module's and the writable-open
//! call in `sqlite.rs`) together.

use std::{
    fmt,
    fs::{File, OpenOptions, Permissions},
    io::{self, Read, Write},
    ops::BitOr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use pos_core::{
    checked_append_identity_expires_at,
    error::CoreError,
    ids::{EntityId, EventId, TimelineId},
    WallTime,
};
use pos_crypto::{subject_data::subject_data_public_header, subject_key::subject_owner_id};
use rand::{rngs::SysRng, TryRng};
use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{sqlite_schema_ddl, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};

/// The reserved file name of the owner append-MAC key (ADR-137 A2).
pub const APPEND_MAC_KEY_FILE_NAME: &str = "subject-append-mac.v1.key";

/// Domain prefix of the keyed request MAC.
const REQUEST_MAC_DOMAIN: &[u8] = b"pigloros/subject-data-append-mac/v1\0";

/// Domain prefix of the request digest stored in a receipt.
const REQUEST_DIGEST_DOMAIN: &[u8] = b"pigloros/subject-data-append-request/v1\0";

/// The exact mode of an admitted key file: a regular file, `0600`, no special bits.
const KEY_FILE_MODE: u32 = 0o100_600;

/// The receipt table, keyed by the 32-byte `operation_key`.
///
/// `subject_owner_id` is exactly `subject:` followed by 32 lowercase hex
/// digits (ADR-091), `request_digest` is the A2 request digest, `event_id` is
/// the canonical upper-case ULID text of the committed Event, and
/// `expires_at` is the store-owned admission time plus the append-identity
/// retention in microseconds. The `CHECK` constraints stand in for `STRICT`.
const SUBJECT_APPEND_RECEIPTS_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "subject_data_append_receipts",
    columns_query: "PRAGMA table_info(subject_data_append_receipts)",
    columns: &[
        SqliteSchemaColumn {
            name: "operation_key",
            kind: "BLOB",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "subject_owner_id",
            kind: "TEXT",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "request_digest",
            kind: "BLOB",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "event_id",
            kind: "TEXT",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "expires_at",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
    ],
    constraints: &[
        "CHECK (typeof(operation_key) = 'blob')",
        "CHECK (length(operation_key) = 32)",
        "CHECK (typeof(subject_owner_id) = 'text')",
        "CHECK (length(subject_owner_id) = 40)",
        "CHECK (substr(subject_owner_id, 1, 8) = 'subject:')",
        "CHECK (substr(subject_owner_id, 9) NOT GLOB '*[^0-9a-f]*')",
        "CHECK (typeof(request_digest) = 'blob')",
        "CHECK (length(request_digest) = 32)",
        "CHECK (typeof(event_id) = 'text')",
        "CHECK (length(event_id) = 26)",
        "CHECK (event_id = upper(event_id))",
        "CHECK (typeof(expires_at) = 'integer')",
    ],
}];

/// Why a receipt or key operation refused. Every variant fails closed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectAppendReceiptRefusalV1 {
    /// The request cannot be bound: a nil subject, a bad field tag or an unrepresentable expiry.
    #[error("subject append receipt request is invalid")]
    InvalidRequest,
    /// The connection is not inside the caller's transaction (autocommit mode).
    #[error("subject append receipt access requires an open transaction")]
    NotInTransaction,
    /// The receipt table could not be read or written.
    #[error("subject append receipts are unreadable")]
    Unreadable,
    /// A stored receipt for the operation key does not parse.
    #[error("subject append receipt is malformed")]
    Malformed,
    /// The receipt row could not be stored.
    #[error("subject append receipt was not stored")]
    NotStored,
    /// The owner append-MAC key could not be loaded or created.
    #[error("subject append MAC key is unavailable")]
    KeyUnavailable,
}

/// What the receipt table says about one operation key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectAppendReceiptLookupV1 {
    /// No receipt exists: the append may proceed and insert its receipt.
    Absent,
    /// A receipt with the same request digest exists for this Event.
    Duplicate(EventId),
    /// A receipt exists with a different request digest.
    OperationConflict,
}

/// One receipt row, inserted in the same commit as its Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectAppendReceiptV1 {
    /// The keyed hash of the caller's retry identity.
    pub operation_key: [u8; 32],
    /// The subject whose data was appended.
    pub subject: EntityId,
    /// The A2 request digest, from [`subject_append_request_digest`].
    pub request_digest: [u8; 32],
    /// The committed Event.
    pub event_id: EventId,
}

/// Compute the A2 request digest bound into a receipt.
///
/// `BLAKE3(domain || subject_owner_id || 0x00 || timeline_bytes16 ||
/// field_tag || 0x00 || predecessor_bytes16_or_zero16 || request_mac)`. A
/// `None` predecessor binds sixteen zero bytes.
///
/// # Errors
/// Returns [`SubjectAppendReceiptRefusalV1::InvalidRequest`] for a nil
/// subject or a `field_tag` that is empty, not ASCII or over 128 bytes.
pub fn subject_append_request_digest(
    subject: EntityId,
    timeline: TimelineId,
    field_tag: &str,
    predecessor: Option<EventId>,
    request_mac: &[u8; 32],
) -> Result<[u8; 32], SubjectAppendReceiptRefusalV1> {
    let owner =
        subject_owner_id(subject).map_err(|_| SubjectAppendReceiptRefusalV1::InvalidRequest)?;
    subject_data_public_header(subject, field_tag)
        .map_err(|_| SubjectAppendReceiptRefusalV1::InvalidRequest)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update(owner.as_bytes());
    hasher.update(&[0]);
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(field_tag.as_bytes());
    hasher.update(&[0]);
    hasher.update(&predecessor.map_or([0; 16], |event| event.inner().to_bytes()));
    hasher.update(request_mac);
    Ok(*hasher.finalize().as_bytes())
}

/// Look up the receipt for `operation_key` against the request's digest.
///
/// The caller must hold `BEGIN IMMEDIATE`. Only "a transaction is open" is
/// enforced here (`is_autocommit()` is false), so a deferred `BEGIN` or a
/// `SAVEPOINT` also passes; the write lock is the caller's duty. Call it after the B3 erasure
/// check and before either crypto callback (ADR-137 A2, A5 gate 5). It reads
/// only. The digest comparison is constant-time.
///
/// # Errors
/// Returns [`SubjectAppendReceiptRefusalV1::NotInTransaction`] when the
/// connection is in autocommit mode,
/// [`SubjectAppendReceiptRefusalV1::Unreadable`] when the read fails
/// (for example, the table is missing) and
/// [`SubjectAppendReceiptRefusalV1::Malformed`] when the stored digest or
/// Event id of a matching row does not parse.
pub fn lookup_subject_append_receipt(
    conn: &Connection,
    operation_key: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<SubjectAppendReceiptLookupV1, SubjectAppendReceiptRefusalV1> {
    require_transaction(conn).and_then(|()| lookup_row(conn, operation_key, request_digest))
}

/// Refuse a connection that is in autocommit mode: A2 needs the caller's transaction.
///
/// This proves a transaction exists, not that it is `BEGIN IMMEDIATE`.
fn require_transaction(conn: &Connection) -> Result<(), SubjectAppendReceiptRefusalV1> {
    if conn.is_autocommit() {
        Err(SubjectAppendReceiptRefusalV1::NotInTransaction)
    } else {
        Ok(())
    }
}

fn lookup_row(
    conn: &Connection,
    operation_key: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<SubjectAppendReceiptLookupV1, SubjectAppendReceiptRefusalV1> {
    conn.query_row(
        "SELECT request_digest, event_id
         FROM subject_data_append_receipts
         WHERE operation_key = ?1",
        params![operation_key.as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0).ok(), row.get::<_, String>(1).ok())),
    )
    .optional()
    .map_err(|_| SubjectAppendReceiptRefusalV1::Unreadable)
    .and_then(|row| {
        row.map_or(
            Ok(SubjectAppendReceiptLookupV1::Absent),
            |(stored, event)| classify(stored, event, request_digest),
        )
    })
}

/// Compare a stored row with the request's digest.
fn classify(
    stored: Option<Vec<u8>>,
    event: Option<String>,
    request_digest: &[u8; 32],
) -> Result<SubjectAppendReceiptLookupV1, SubjectAppendReceiptRefusalV1> {
    stored
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .ok_or(SubjectAppendReceiptRefusalV1::Malformed)
        .and_then(|digest| {
            if blake3::Hash::from_bytes(digest) == blake3::Hash::from_bytes(*request_digest) {
                event
                    .and_then(|text| text.parse::<ulid::Ulid>().ok())
                    .map(|ulid| SubjectAppendReceiptLookupV1::Duplicate(EventId::from_ulid(ulid)))
                    .ok_or(SubjectAppendReceiptRefusalV1::Malformed)
            } else {
                Ok(SubjectAppendReceiptLookupV1::OperationConflict)
            }
        })
}

/// Insert the receipt of a committed append, expiring after the retention horizon.
///
/// The caller must hold `BEGIN IMMEDIATE` and call it in the same transaction
/// as the Event append; only that a transaction is open is enforced (a
/// deferred `BEGIN` or `SAVEPOINT` also passes). `admitted_at`
/// is the store-owned admission clock reading; the clock governs retention
/// only, never authority. An existing row for the operation key is never
/// replaced.
///
/// # Errors
/// Returns [`SubjectAppendReceiptRefusalV1::NotInTransaction`] when the
/// connection is in autocommit mode,
/// [`SubjectAppendReceiptRefusalV1::InvalidRequest`] for a nil
/// subject or an expiry that overflows `u64` or `i64`, and
/// [`SubjectAppendReceiptRefusalV1::NotStored`] when the insert fails.
pub fn insert_subject_append_receipt(
    conn: &Connection,
    receipt: &SubjectAppendReceiptV1,
    admitted_at: WallTime,
) -> Result<(), SubjectAppendReceiptRefusalV1> {
    require_transaction(conn).and_then(|()| insert_row(conn, receipt, admitted_at))
}

fn insert_row(
    conn: &Connection,
    receipt: &SubjectAppendReceiptV1,
    admitted_at: WallTime,
) -> Result<(), SubjectAppendReceiptRefusalV1> {
    let expires_at = checked_append_identity_expires_at(admitted_at)
        .ok()
        .and_then(|expiry| i64::try_from(expiry.as_micros()).ok());
    match (subject_owner_id(receipt.subject).ok(), expires_at) {
        (Some(owner), Some(expires_at)) => conn
            .execute(
                "INSERT INTO subject_data_append_receipts
                 (operation_key, subject_owner_id, request_digest, event_id, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    receipt.operation_key.as_slice(),
                    owner,
                    receipt.request_digest.as_slice(),
                    receipt.event_id.to_string(),
                    expires_at,
                ],
            )
            .map(|_| ())
            .map_err(|_| SubjectAppendReceiptRefusalV1::NotStored),
        _ => Err(SubjectAppendReceiptRefusalV1::InvalidRequest),
    }
}

/// Delete every receipt whose retention has ended at `now`, returning the count.
///
/// This is the asynchronous maintenance purge of ADR-137 A2, not part of the
/// combined append: it runs in its own transaction (autocommit is fine) and
/// takes no `require_transaction` guard, unlike lookup and insert.
///
/// # Errors
/// Returns [`SubjectAppendReceiptRefusalV1::Unreadable`] when the delete fails.
pub fn purge_expired_subject_append_receipts(
    conn: &Connection,
    now: WallTime,
) -> Result<usize, SubjectAppendReceiptRefusalV1> {
    conn.execute(
        "DELETE FROM subject_data_append_receipts WHERE expires_at <= ?1",
        params![i64::try_from(now.as_micros()).unwrap_or(i64::MAX)],
    )
    .map_err(|_| SubjectAppendReceiptRefusalV1::Unreadable)
}

/// The owner append-MAC key: 32 random bytes held for the process lifetime.
///
/// It is never logged and is wiped on drop. The bytes live in one heap box so
/// that moving the key never leaves a stack copy behind, and every load or
/// create fills that box in place. It confers no authority and protects no
/// confidentiality beyond the receipt's request MAC.
pub struct SubjectAppendMacKeyV1(Box<Zeroizing<[u8; 32]>>);

impl fmt::Debug for SubjectAppendMacKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectAppendMacKeyV1(..)")
    }
}

/// `open(2)` flags for reading the key file: no symlinks, no inheritance, no blocking.
fn read_key_flags() -> i32 {
    libc::O_NOFOLLOW
        .bitor(libc::O_CLOEXEC)
        .bitor(libc::O_NONBLOCK)
}

type Entropy = fn(&mut [u8]) -> Result<(), ()>;
type KeyReader = fn(&Path, u32, &mut [u8; 32]) -> io::Result<()>;
type KeyPersister = fn(&mut File, &[u8; 32]) -> io::Result<()>;

fn system_entropy(bytes: &mut [u8]) -> Result<(), ()> {
    SysRng.try_fill_bytes(bytes).map_err(|_| ())
}

/// The effects of key custody, injectable so each failure can be pinned.
struct KeyIo {
    euid: u32,
    fill: Entropy,
    read: KeyReader,
    persist: KeyPersister,
}

impl SubjectAppendMacKeyV1 {
    /// Load the key file in `directory`, creating it when missing or corrupt.
    ///
    /// The caller holds the E16 lifetime lock on the already admitted state
    /// directory (ADR-137 A2). A missing file is created. A file that is not
    /// a regular `0600` file with one link, owned by the current effective
    /// user and exactly 32 bytes long is corrupt: its entry is removed and a
    /// new key is created with `O_EXCL`, `0600` (forced with `fchmod`, so a
    /// restrictive umask cannot weaken it), no-follow, and a file plus
    /// directory sync. Retries of receipts made under a lost key then answer
    /// `OperationConflict`. Any other read failure (descriptor exhaustion, an
    /// I/O error, a permission error) leaves the file untouched.
    ///
    /// # Errors
    /// Returns [`SubjectAppendReceiptRefusalV1::KeyUnavailable`] when the key
    /// cannot be read for a reason other than absence or corruption, when the
    /// corrupt entry cannot be removed, or when the new key cannot be created
    /// durably. A new file whose write or sync failed is removed again.
    pub fn load_or_create(directory: &Path) -> Result<Self, SubjectAppendReceiptRefusalV1> {
        Self::load_or_create_with(
            directory,
            &KeyIo {
                euid: rustix::process::geteuid().as_raw(),
                fill: system_entropy,
                read: read_key_file,
                persist: persist_key,
            },
        )
    }

    fn load_or_create_with(
        directory: &Path,
        io: &KeyIo,
    ) -> Result<Self, SubjectAppendReceiptRefusalV1> {
        let path = directory.join(APPEND_MAC_KEY_FILE_NAME);
        let mut key = Self(Box::new(Zeroizing::new([0; 32])));
        match (io.read)(&path, io.euid, &mut key.0) {
            Ok(()) => Ok(key),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_key_file(directory, &path, io, &mut key.0).map(|()| key)
            }
            Err(error) if is_corrupt_key(&error) => std::fs::remove_file(&path)
                .map_err(|_| SubjectAppendReceiptRefusalV1::KeyUnavailable)
                .and_then(|()| create_key_file(directory, &path, io, &mut key.0))
                .map(|()| key),
            Err(_) => Err(SubjectAppendReceiptRefusalV1::KeyUnavailable),
        }
    }

    /// The A2 request MAC: keyed BLAKE3 over `domain || field_tag || 0x00 || plaintext`.
    ///
    /// The `0x00` after the variable-length `field_tag` is an addition to the
    /// ADR-137 A2 text (`domain || field_tag || plaintext`), which is
    /// ambiguous between tag and plaintext. It needs an ADR erratum: the
    /// preimage is `domain || field_tag || 0x00 || plaintext` with a
    /// NUL-free `field_tag`, which makes the split unambiguous.
    ///
    /// # Errors
    /// Returns [`SubjectAppendReceiptRefusalV1::InvalidRequest`] for a
    /// `field_tag` containing a NUL byte.
    pub fn request_mac(
        &self,
        field_tag: &str,
        plaintext: &[u8],
    ) -> Result<[u8; 32], SubjectAppendReceiptRefusalV1> {
        if field_tag.as_bytes().contains(&0) {
            return Err(SubjectAppendReceiptRefusalV1::InvalidRequest);
        }
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(REQUEST_MAC_DOMAIN);
        hasher.update(field_tag.as_bytes());
        hasher.update(&[0]);
        hasher.update(plaintext);
        Ok(*hasher.finalize().as_bytes())
    }
}

/// Whether a read failure means the key file has a wrong shape.
///
/// A wrong mode, owner, link count or length reads as `InvalidData`, a file
/// that shrank mid-read as `UnexpectedEof`, and a symlink refused by
/// `O_NOFOLLOW` as `ELOOP`. Everything else is not evidence of corruption.
fn is_corrupt_key(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    ) || error.raw_os_error() == Some(libc::ELOOP)
}

/// Read and admit the key file into `key`, refusing symlinks, devices and wrong shapes.
fn read_key_file(path: &Path, euid: u32, key: &mut [u8; 32]) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(read_key_flags())
        .open(path)
        .and_then(|mut file| {
            file.metadata().and_then(|metadata| {
                if metadata.mode() == KEY_FILE_MODE
                    && metadata.uid() == euid
                    && metadata.nlink() == 1
                    && metadata.len() == 32
                {
                    file.read_exact(key)
                } else {
                    Err(io::ErrorKind::InvalidData.into())
                }
            })
        })
}

/// Force `0600` regardless of the umask, then write and sync the key bytes.
fn persist_key(file: &mut File, key: &[u8; 32]) -> io::Result<()> {
    file.set_permissions(Permissions::from_mode(0o600))
        .and_then(|()| file.write_all(key))
        .and_then(|()| file.sync_all())
}

/// Fill a new key in place and store it durably under the reserved name.
///
/// A file whose permission, write or sync step failed is unlinked at once so
/// a partial key is never left under the reserved name.
fn create_key_file(
    directory: &Path,
    path: &Path,
    io: &KeyIo,
    key: &mut [u8; 32],
) -> Result<(), SubjectAppendReceiptRefusalV1> {
    (io.fill)(key)
        .ok()
        .and_then(|()| {
            // `create_new` is `O_CREAT | O_EXCL`, which already refuses a symlink
            // at the last component, and std opens with `O_CLOEXEC`.
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .ok()
        })
        .and_then(|mut file| {
            let stored = (io.persist)(&mut file, key).is_ok();
            if !stored {
                drop(std::fs::remove_file(path));
            }
            stored.then_some(())
        })
        .and_then(|()| {
            File::open(directory)
                .and_then(|handle| handle.sync_all())
                .ok()
        })
        .ok_or(SubjectAppendReceiptRefusalV1::KeyUnavailable)
}

impl SqliteStore {
    /// Create the receipt table on a writable open, then validate its exact shape.
    pub(super) fn prepare_subject_append_receipts_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&sqlite_schema_ddl(SUBJECT_APPEND_RECEIPTS_SCHEMA_TABLES))
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                SUBJECT_APPEND_RECEIPTS_SCHEMA_TABLES
                    .iter()
                    .try_for_each(|table| self.validate_sqlite_schema_table(table))
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
