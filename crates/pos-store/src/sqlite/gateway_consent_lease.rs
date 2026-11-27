#![cfg(any(test, feature = "test-support"))]
//! ADR-137 L2-L6: the Gateway consent lease, its store generation and fence.
//!
//! In profile composition exactly one Gateway process per store holds a
//! [`GatewayConsentLeaseV1`]. It is built only by
//! [`acquire_gateway_consent_lease`] and follows ADR-137 L4 steps 1, 3 and 5:
//!
//! 1. pre-screen the main file, which gives the coordination key
//!    `(device, inode)`;
//! 2. open the existing `gateway-consent-lease.v1.<dev016x>.<ino016x>.lock`
//!    entry of the ADR-123 coordination child and take `flock(LOCK_EX |
//!    LOCK_NB)` on it, so contention returns
//!    [`GatewayConsentLeaseErrorV1::LeaseHeld`] and a missing child or entry
//!    returns [`GatewayConsentLeaseErrorV1::LeaseUnavailable`]; nothing here
//!    creates either (ADR-123 §3a installation does);
//! 3. require the identity that the ADR-123 §5 proof produced to equal the
//!    key, else [`GatewayConsentLeaseErrorV1::LeaseIdentityMismatch`];
//! 4. commit the L5 generation in one shared-store `BEGIN IMMEDIATE`.
//!
//! The Gateway mode lock (L4 step 2) and the full ADR-123 setup (step 4) belong
//! to the composition root, which also owns the lease's lifetime: the lease
//! holds its descriptor until it is dropped, and a quarantined authority keeps
//! it until process exit. [`require_current_consent_lease_generation`] is the
//! L6 store fence that every guarded transaction runs first.
//!
//! Everything here stays test-support gated until owner activation (#1438).
//!
//! Only a writable open creates and validates the table, so a read-only store
//! fails closed: acquisition cannot begin its write transaction.

use std::cmp::Ordering;
use std::fmt;
use std::num::NonZeroU64;
use std::path::Path;

use pos_core::CoreError;
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use rusqlite::Connection;
use rustix::fd::OwnedFd;
use rustix::fs::{self, FlockOperation, Mode, OFlags};
use rustix::io::{self, Errno};

use super::{sqlite_schema_ddl, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};
use crate::owner_store_interlock::{
    open_coordination_directory, reserved_names, verify_lock_entry, CheckedNamespace, RESOLVE,
};

/// The L5 singleton table that holds the lease generation.
///
/// ADR-137 declares it `STRICT`. The shared DDL builder cannot emit that
/// keyword, so every column carries the equivalent `typeof` check instead.
const GATEWAY_CONSENT_LEASE_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "gateway_consent_lease",
    columns_query: "PRAGMA table_info(gateway_consent_lease)",
    columns: &[
        SqliteSchemaColumn {
            name: "singleton",
            kind: "INTEGER",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "format_version",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
        SqliteSchemaColumn {
            name: "generation",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
    ],
    constraints: &[
        "CHECK (typeof(singleton) = 'integer')",
        "CHECK (singleton = 1)",
        "CHECK (typeof(format_version) = 'integer')",
        "CHECK (format_version = 1)",
        "CHECK (typeof(generation) = 'integer')",
        "CHECK (generation >= 1)",
    ],
}];

/// Reads the stored generation as one integer.
///
/// `0` means no row, `-1` means anything other than exactly one valid row, and
/// a positive value is the valid row's generation.
const READ_GENERATION_SQL: &str = "SELECT CASE
        WHEN count(*) = 0 THEN 0
        WHEN count(*) = 1
            AND sum(typeof(singleton) = 'integer' AND singleton = 1
                AND typeof(format_version) = 'integer' AND format_version = 1
                AND typeof(generation) = 'integer' AND generation >= 1) = 1
        THEN max(generation)
        ELSE -1
     END
     FROM gateway_consent_lease";

/// Stores the next generation in the singleton row.
const WRITE_GENERATION_SQL: &str = "INSERT INTO gateway_consent_lease
        (singleton, format_version, generation)
     VALUES (1, 1, ?1)
     ON CONFLICT (singleton) DO UPDATE SET generation = excluded.generation";

/// Whether the ADR-137 I6 consent revocation journal holds no row.
const JOURNAL_EMPTY_SQL: &str = "SELECT NOT EXISTS (SELECT 1 FROM consent_revocation_journal)";

const LOCK_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NONBLOCK);

/// A non-zero lease generation, the `G` of ADR-137 L5.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConsentLeaseGenerationV1(NonZeroU64);

impl ConsentLeaseGenerationV1 {
    /// The generation `value`, or `None` for zero.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(generation) => Some(Self(generation)),
            None => None,
        }
    }

    /// The generation as an integer, always at least one.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Why acquiring or fencing the Gateway consent lease refused.
///
/// Every variant fails closed and carries no path or OS diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayConsentLeaseErrorV1 {
    /// The pre-screen failed or the coordination child or lease entry is
    /// missing or unsafe.
    LeaseUnavailable,
    /// Another process holds the lease.
    LeaseHeld,
    /// The proven store identity differs from the coordination key.
    LeaseIdentityMismatch,
    /// No generation row exists although the consent journal has rows.
    LeaseStateMissing,
    /// The generation row or its table is not exactly one valid row.
    LeaseStateCorrupt,
    /// The generation cannot be incremented.
    GenerationExhausted,
    /// The stored generation differs from the caller's.
    LeaseFenced,
    /// The caller holds no store transaction for the fence read.
    NotInTransaction,
    /// The store transaction or the journal read failed.
    StoreUnreadable,
}

impl fmt::Display for GatewayConsentLeaseErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LeaseUnavailable => "gateway consent lease unavailable",
            Self::LeaseHeld => "gateway consent lease held",
            Self::LeaseIdentityMismatch => "gateway consent lease identity mismatch",
            Self::LeaseStateMissing => "gateway consent lease state missing",
            Self::LeaseStateCorrupt => "gateway consent lease state corrupt",
            Self::GenerationExhausted => "gateway consent lease generation exhausted",
            Self::LeaseFenced => "gateway consent lease fenced",
            Self::NotInTransaction => "gateway consent lease fence needs a transaction",
            Self::StoreUnreadable => "gateway consent lease store unreadable",
        })
    }
}

impl std::error::Error for GatewayConsentLeaseErrorV1 {}

impl From<rusqlite::Error> for GatewayConsentLeaseErrorV1 {
    fn from(_: rusqlite::Error) -> Self {
        Self::StoreUnreadable
    }
}

/// The held Gateway consent lease: the lock descriptor and its generation.
///
/// Dropping it releases the OS lock, so the composition root retains it for
/// the process lifetime. It conveys no authority beyond the generation.
#[must_use = "retain the lease for the process lifetime"]
#[derive(Debug)]
pub struct GatewayConsentLeaseV1 {
    generation: ConsentLeaseGenerationV1,
    store_file_id: SubjectStoreFileIdV1,
    _lock: OwnedFd,
}

impl GatewayConsentLeaseV1 {
    /// The generation committed by this acquisition.
    #[must_use]
    pub const fn generation(&self) -> ConsentLeaseGenerationV1 {
        self.generation
    }

    /// The canonical store identity that keys this lease (ADR-137 L2).
    #[must_use]
    pub const fn store_file_id(&self) -> SubjectStoreFileIdV1 {
        self.store_file_id
    }
}

/// Acquire the Gateway consent lease and commit its new generation.
///
/// `test_database_directory` and `main_basename` name the store's main file
/// exactly as ADR-123 coordination does, and `proven_identity` is the identity
/// of the ADR-123 §5 actual-native proof. Every step is nonblocking and the
/// first failing step returns its own refusal, so no later step runs. A
/// refusal after the lock was taken releases it again.
///
/// # Errors
/// Returns [`GatewayConsentLeaseErrorV1::LeaseUnavailable`] for a failed
/// pre-screen or a missing or unsafe child or entry,
/// [`GatewayConsentLeaseErrorV1::LeaseHeld`] on contention,
/// [`GatewayConsentLeaseErrorV1::LeaseIdentityMismatch`] when the proven
/// identity differs from the key, and the L5 refusals
/// ([`GatewayConsentLeaseErrorV1::LeaseStateMissing`],
/// [`GatewayConsentLeaseErrorV1::LeaseStateCorrupt`],
/// [`GatewayConsentLeaseErrorV1::GenerationExhausted`] and
/// [`GatewayConsentLeaseErrorV1::StoreUnreadable`]).
pub fn acquire_gateway_consent_lease(
    store: &SqliteStore,
    test_database_directory: &Path,
    main_basename: &str,
    proven_identity: SubjectStoreFileIdV1,
) -> Result<GatewayConsentLeaseV1, GatewayConsentLeaseErrorV1> {
    CheckedNamespace::open(test_database_directory, main_basename)
        .and_then(|namespace| {
            lock_lease(&namespace).map(|lock| {
                let key = SubjectStoreFileIdV1::Linux {
                    device: namespace.main.stat.st_dev,
                    inode: namespace.main.stat.st_ino,
                };
                (lock, key)
            })
        })
        .map_err(classify)
        .and_then(|(lock, key)| {
            if key == proven_identity {
                commit_generation(&store.conn).map(|generation| GatewayConsentLeaseV1 {
                    generation,
                    store_file_id: key,
                    _lock: lock,
                })
            } else {
                Err(GatewayConsentLeaseErrorV1::LeaseIdentityMismatch)
            }
        })
}

/// Require that the store still holds the generation `expected` (ADR-137 L6).
///
/// Call it first inside the guarded transaction, which is a `BEGIN IMMEDIATE`
/// for a write and a read-snapshot transaction for a read, so the generation
/// is read in the same snapshot as the data it guards. It reads only.
///
/// # Errors
/// Returns [`GatewayConsentLeaseErrorV1::NotInTransaction`] in autocommit
/// mode, and [`GatewayConsentLeaseErrorV1::LeaseFenced`] when the stored
/// generation differs, the row is missing or corrupt, or the read fails. The
/// caller then moves its authority to `Quarantined` (L8).
pub fn require_current_consent_lease_generation(
    conn: &Connection,
    expected: ConsentLeaseGenerationV1,
) -> Result<(), GatewayConsentLeaseErrorV1> {
    if conn.is_autocommit() {
        return Err(GatewayConsentLeaseErrorV1::NotInTransaction);
    }
    read_generation(conn)
        .map_err(|_| GatewayConsentLeaseErrorV1::LeaseFenced)
        .and_then(|stored| {
            if i64::try_from(expected.get()) == Ok(stored) {
                Ok(())
            } else {
                Err(GatewayConsentLeaseErrorV1::LeaseFenced)
            }
        })
}

/// Map a lock-step failure: only the `flock` step reports contention.
fn classify(error: Errno) -> GatewayConsentLeaseErrorV1 {
    if error == Errno::WOULDBLOCK {
        GatewayConsentLeaseErrorV1::LeaseHeld
    } else {
        GatewayConsentLeaseErrorV1::LeaseUnavailable
    }
}

/// Open the existing lease entry of the coordination child and lock it.
///
/// The entry is locked first and then verified: it must be a private singly
/// linked regular file that is still the entry of that name, so a swapped or
/// unsafe entry refuses. A missing child or entry refuses; nothing is created
/// or unlinked.
fn lock_lease(namespace: &CheckedNamespace) -> io::Result<OwnedFd> {
    open_coordination_directory(&namespace.directory).and_then(|child| {
        let [_, name, _] = reserved_names(&namespace.main.stat);
        fs::openat2(&child, &name, LOCK_FLAGS, Mode::empty(), RESOLVE).and_then(|descriptor| {
            fs::flock(&descriptor, FlockOperation::NonBlockingLockExclusive)
                .and_then(|()| verify_lock_entry(&child, &name, &descriptor))
                .map(|()| descriptor)
        })
    })
}

/// Read the stored generation code of [`READ_GENERATION_SQL`].
fn read_generation(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(READ_GENERATION_SQL, [], |row| row.get::<_, i64>(0))
}

/// Run the L5 transaction: one `BEGIN IMMEDIATE` that commits the new generation.
fn commit_generation(
    conn: &Connection,
) -> Result<ConsentLeaseGenerationV1, GatewayConsentLeaseErrorV1> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(GatewayConsentLeaseErrorV1::from)
        .and_then(|()| {
            next_generation(conn)
                .and_then(|generation| {
                    conn.execute_batch("COMMIT")
                        .map(|()| generation)
                        .map_err(GatewayConsentLeaseErrorV1::from)
                })
                .inspect_err(|_| {
                    // A refused step or a failed COMMIT leaves the transaction open.
                    conn.execute_batch("ROLLBACK").ok();
                })
        })
}

/// Decide and store the next generation inside the open transaction.
fn next_generation(
    conn: &Connection,
) -> Result<ConsentLeaseGenerationV1, GatewayConsentLeaseErrorV1> {
    read_generation(conn)
        .map_err(|_| GatewayConsentLeaseErrorV1::LeaseStateCorrupt)
        .and_then(|stored| match stored.cmp(&0) {
            Ordering::Less => Err(GatewayConsentLeaseErrorV1::LeaseStateCorrupt),
            Ordering::Equal => journal_is_empty(conn).and_then(|empty| {
                if empty {
                    Ok(stored)
                } else {
                    Err(GatewayConsentLeaseErrorV1::LeaseStateMissing)
                }
            }),
            Ordering::Greater => Ok(stored),
        })
        .and_then(|stored| {
            stored
                .checked_add(1)
                .ok_or(GatewayConsentLeaseErrorV1::GenerationExhausted)
                .map(|next| (stored, next))
        })
        .and_then(|(stored, next)| {
            conn.execute(WRITE_GENERATION_SQL, [next])
                .map_err(GatewayConsentLeaseErrorV1::from)
                .map(|_| {
                    // `stored` is never negative here, so this equals `next`.
                    ConsentLeaseGenerationV1(NonZeroU64::MIN.saturating_add(stored.unsigned_abs()))
                })
        })
}

fn journal_is_empty(conn: &Connection) -> Result<bool, GatewayConsentLeaseErrorV1> {
    conn.query_row(JOURNAL_EMPTY_SQL, [], |row| row.get::<_, bool>(0))
        .map_err(GatewayConsentLeaseErrorV1::from)
}

impl SqliteStore {
    /// Create the L5 table on a writable open, then validate its exact shape.
    pub(super) fn prepare_gateway_consent_lease_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&sqlite_schema_ddl(GATEWAY_CONSENT_LEASE_SCHEMA_TABLES))
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                GATEWAY_CONSENT_LEASE_SCHEMA_TABLES
                    .iter()
                    .try_for_each(|table| self.validate_sqlite_schema_table(table))
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
