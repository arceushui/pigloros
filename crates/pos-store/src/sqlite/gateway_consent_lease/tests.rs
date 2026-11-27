#![cfg(any(test, feature = "test-support"))]
//! ADR-137 L2-L6: the lease lock, the generation row and the store fence.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;

use super::{
    acquire_gateway_consent_lease, require_current_consent_lease_generation,
    ConsentLeaseGenerationV1, GatewayConsentLeaseErrorV1, GatewayConsentLeaseV1,
};
use crate::owner_store_installation::install_owner_store_namespace_v1;
use crate::sqlite::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Refusal = GatewayConsentLeaseErrorV1;

const MAIN: &str = "main.db";
const CHILD: &str = ".pigloros-store-namespace-v1";
/// A `SQLite` 3 header in WAL mode, which the installation step requires.
const MAIN_BYTES: [u8; 20] = *b"SQLite format 3\0\x10\x00\x02\x02";

struct Fixture {
    directory: tempfile::TempDir,
    identity: SubjectStoreFileIdV1,
    entry: std::path::PathBuf,
}

impl Fixture {
    fn new(installed: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let mut main = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join(MAIN))?;
        main.write_all(&MAIN_BYTES)?;
        drop(main);
        if installed {
            install_owner_store_namespace_v1(directory.path(), MAIN)?;
        }
        let metadata = fs::metadata(directory.path().join(MAIN))?;
        let (device, inode) = (metadata.dev(), metadata.ino());
        let entry = directory.path().join(CHILD).join(format!(
            "gateway-consent-lease.v1.{device:016x}.{inode:016x}.lock"
        ));
        Ok(Self {
            directory,
            identity: SubjectStoreFileIdV1::Linux { device, inode },
            entry,
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn acquire(&self, store: &SqliteStore) -> Result<GatewayConsentLeaseV1, Refusal> {
        self.acquire_as(store, self.identity)
    }

    fn acquire_as(
        &self,
        store: &SqliteStore,
        identity: SubjectStoreFileIdV1,
    ) -> Result<GatewayConsentLeaseV1, Refusal> {
        acquire_gateway_consent_lease(store, self.path(), MAIN, identity)
    }

    /// The generation a successful acquisition committed, with the lease released.
    fn generation(&self, store: &SqliteStore) -> Result<u64, Refusal> {
        self.acquire(store).map(|lease| lease.generation().get())
    }
}

fn stored(store: &SqliteStore) -> rusqlite::Result<Vec<(i64, i64, i64)>> {
    let mut statement = store.conn.prepare(
        "SELECT singleton, format_version, generation FROM gateway_consent_lease ORDER BY 1",
    )?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    rows.collect()
}

/// Re-enables check constraints when dropped, even after a failed insert.
struct ConstraintsIgnored<'a>(&'a rusqlite::Connection);

impl Drop for ConstraintsIgnored<'_> {
    fn drop(&mut self) {
        self.0
            .execute_batch("PRAGMA ignore_check_constraints = OFF")
            .ok();
    }
}

fn insert_unchecked(store: &SqliteStore, values: &str) -> rusqlite::Result<()> {
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    let _reset = ConstraintsIgnored(&store.conn);
    store.conn.execute_batch(&format!(
        "INSERT INTO gateway_consent_lease (singleton, format_version, generation)
         VALUES {values}"
    ))
}

fn stub_journal(store: &SqliteStore, rows: bool) -> rusqlite::Result<()> {
    store
        .conn
        .execute_batch("CREATE TABLE consent_revocation_journal (id INTEGER NOT NULL)")?;
    if rows {
        store
            .conn
            .execute_batch("INSERT INTO consent_revocation_journal VALUES (1)")?;
    }
    Ok(())
}

/// A fresh store with the empty journal that L5 requires before it inserts generation one.
fn store_with_empty_journal() -> Result<SqliteStore, Box<dyn std::error::Error>> {
    let store = SqliteStore::open_in_memory()?;
    stub_journal(&store, false)?;
    Ok(store)
}

#[test]
fn a_generation_is_never_zero() {
    assert_eq!(ConsentLeaseGenerationV1::new(0), None);
    assert_eq!(
        ConsentLeaseGenerationV1::new(1).map(ConsentLeaseGenerationV1::get),
        Some(1)
    );
    assert_eq!(
        ConsentLeaseGenerationV1::new(u64::MAX).map(ConsentLeaseGenerationV1::get),
        Some(u64::MAX)
    );
}

#[test]
fn every_refusal_has_one_fixed_text() {
    let expected = [
        (
            Refusal::LeaseUnavailable,
            "gateway consent lease unavailable",
        ),
        (Refusal::LeaseHeld, "gateway consent lease held"),
        (
            Refusal::LeaseIdentityMismatch,
            "gateway consent lease identity mismatch",
        ),
        (
            Refusal::LeaseStateMissing,
            "gateway consent lease state missing",
        ),
        (
            Refusal::LeaseStateCorrupt,
            "gateway consent lease state corrupt",
        ),
        (
            Refusal::GenerationExhausted,
            "gateway consent lease generation exhausted",
        ),
        (Refusal::LeaseFenced, "gateway consent lease fenced"),
        (
            Refusal::NotInTransaction,
            "gateway consent lease fence needs a transaction",
        ),
        (
            Refusal::StoreUnreadable,
            "gateway consent lease store unreadable",
        ),
    ];
    for (refusal, text) in expected {
        assert_eq!(refusal.to_string(), text);
    }
}

#[test]
fn a_writable_open_creates_an_empty_singleton_table() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    assert_eq!(stored(&store)?, Vec::new());
    Ok(())
}

#[test]
fn an_incompatible_table_refuses_a_writable_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lease.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    rusqlite::Connection::open(path)?.execute_batch(
        "DROP TABLE gateway_consent_lease;
         CREATE TABLE gateway_consent_lease (generation INTEGER NOT NULL);",
    )?;
    let refusal = SqliteStore::open(path).err().ok_or("opened")?;
    assert!(refusal.to_string().contains("gateway_consent_lease"));
    Ok(())
}

#[test]
fn the_first_acquisition_commits_generation_one() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = store_with_empty_journal()?;
    let lease = fixture.acquire(&store)?;
    assert_eq!(lease.generation().get(), 1);
    assert_eq!(lease.store_file_id(), fixture.identity);
    assert_eq!(stored(&store)?, vec![(1, 1, 1)]);
    assert!(store.conn.is_autocommit());
    Ok(())
}

#[test]
fn each_acquisition_after_a_release_increments_the_generation() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = store_with_empty_journal()?;
    assert_eq!(fixture.generation(&store), Ok(1));
    assert_eq!(fixture.generation(&store), Ok(2));
    assert_eq!(fixture.generation(&store), Ok(3));
    assert_eq!(stored(&store)?, vec![(1, 1, 3)]);
    Ok(())
}

#[test]
fn contention_refuses_at_once_and_writes_nothing() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = store_with_empty_journal()?;
    let held = fixture.acquire(&store)?;
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseHeld));
    assert_eq!(stored(&store)?, vec![(1, 1, 1)]);
    drop(held);
    assert_eq!(fixture.generation(&store), Ok(2));
    Ok(())
}

#[test]
fn a_missing_child_or_entry_refuses_and_creates_nothing() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let bare = Fixture::new(false)?;
    assert_eq!(bare.generation(&store), Err(Refusal::LeaseUnavailable));
    assert!(!bare.path().join(CHILD).exists());

    let installed = Fixture::new(true)?;
    fs::remove_file(&installed.entry)?;
    assert_eq!(installed.generation(&store), Err(Refusal::LeaseUnavailable));
    assert!(!installed.entry.exists());
    assert_eq!(stored(&store)?, Vec::new());
    Ok(())
}

#[test]
fn an_unsafe_entry_is_unavailable_not_held() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    fs::set_permissions(&fixture.entry, fs::Permissions::from_mode(0o644))?;
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseUnavailable));
    Ok(())
}

#[test]
fn an_unsafe_entry_locked_elsewhere_is_unavailable_not_held() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    let other = fixture.acquire(&store)?;
    fs::set_permissions(&fixture.entry, fs::Permissions::from_mode(0o644))?;
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseUnavailable));
    drop(other);
    Ok(())
}

#[test]
fn a_failed_pre_screen_is_unavailable() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    let missing = fixture.path().join("absent");
    assert_eq!(
        acquire_gateway_consent_lease(&store, &missing, MAIN, fixture.identity).err(),
        Some(Refusal::LeaseUnavailable)
    );
    assert_eq!(
        acquire_gateway_consent_lease(&store, fixture.path(), "other.db", fixture.identity).err(),
        Some(Refusal::LeaseUnavailable)
    );
    Ok(())
}

#[test]
fn a_foreign_identity_releases_the_lease_and_spends_no_generation() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = store_with_empty_journal()?;
    let SubjectStoreFileIdV1::Linux { device, inode } = fixture.identity else {
        return Err("not a Linux identity".into());
    };
    for foreign in [
        SubjectStoreFileIdV1::Linux {
            device: device.wrapping_add(1),
            inode,
        },
        SubjectStoreFileIdV1::Linux {
            device,
            inode: inode.wrapping_add(1),
        },
        SubjectStoreFileIdV1::Windows {
            volume_serial: 1,
            file_index: 1,
        },
    ] {
        assert_eq!(
            fixture.acquire_as(&store, foreign).err(),
            Some(Refusal::LeaseIdentityMismatch)
        );
    }
    assert_eq!(stored(&store)?, Vec::new());
    assert_eq!(fixture.generation(&store), Ok(1));
    Ok(())
}

#[test]
fn a_missing_row_with_a_journal_row_is_permanently_missing() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    stub_journal(&store, true)?;
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseStateMissing));
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseStateMissing));
    assert_eq!(stored(&store)?, Vec::new());
    assert!(store.conn.is_autocommit());
    Ok(())
}

#[test]
fn a_missing_row_with_an_empty_journal_starts_at_one() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    stub_journal(&store, false)?;
    assert_eq!(fixture.generation(&store), Ok(1));
    Ok(())
}

#[test]
fn a_missing_row_needs_a_readable_journal() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    assert_eq!(fixture.generation(&store), Err(Refusal::StoreUnreadable));
    assert_eq!(stored(&store)?, Vec::new());
    assert!(store.conn.is_autocommit());
    Ok(())
}

#[test]
fn a_present_row_ignores_the_journal() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    insert_unchecked(&store, "(1, 1, 4)")?;
    stub_journal(&store, true)?;
    assert_eq!(fixture.generation(&store), Ok(5));
    store
        .conn
        .execute_batch("DROP TABLE consent_revocation_journal")?;
    assert_eq!(fixture.generation(&store), Ok(6));
    Ok(())
}

#[test]
fn anything_but_one_valid_row_is_corrupt() -> TestResult {
    let cases = [
        ("(1, 2, 1)", 1),
        ("(1, 1, 0)", 1),
        ("(1, 1, -5)", 1),
        ("(2, 1, 1)", 1),
        ("(1, 1, 'x')", 1),
        ("(1, 'x', 1)", 1),
        ("(1, 1, 1), (2, 1, 1)", 2),
    ];
    for (values, rows) in cases {
        let fixture = Fixture::new(true)?;
        let store = SqliteStore::open_in_memory()?;
        insert_unchecked(&store, values)?;
        assert_eq!(
            fixture.generation(&store),
            Err(Refusal::LeaseStateCorrupt),
            "{values}"
        );
        let remaining: i64 =
            store
                .conn
                .query_row("SELECT count(*) FROM gateway_consent_lease", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(remaining, rows, "{values} was left unchanged");
        assert!(store.conn.is_autocommit());
    }
    Ok(())
}

#[test]
fn an_unreadable_table_is_corrupt() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    store
        .conn
        .execute_batch("DROP TABLE gateway_consent_lease")?;
    assert_eq!(fixture.generation(&store), Err(Refusal::LeaseStateCorrupt));
    Ok(())
}

#[test]
fn the_last_representable_generation_is_the_limit() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    insert_unchecked(&store, &format!("(1, 1, {})", i64::MAX - 1))?;
    assert_eq!(fixture.generation(&store), Ok(i64::MAX.unsigned_abs()));
    assert_eq!(
        fixture.generation(&store),
        Err(Refusal::GenerationExhausted)
    );
    assert_eq!(stored(&store)?, vec![(1, 1, i64::MAX)]);
    Ok(())
}

#[test]
fn an_open_transaction_refuses_the_write_transaction() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    store.conn.execute_batch("BEGIN")?;
    assert_eq!(fixture.generation(&store), Err(Refusal::StoreUnreadable));
    store.conn.execute_batch("ROLLBACK")?;
    assert_eq!(stored(&store)?, Vec::new());
    Ok(())
}

#[test]
fn a_read_only_store_cannot_begin_the_write_transaction() -> TestResult {
    let fixture = Fixture::new(true)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lease.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    let store = SqliteStore::open_read_only(path)?;
    assert_eq!(fixture.generation(&store), Err(Refusal::StoreUnreadable));
    Ok(())
}

fn fenced(store: &SqliteStore, expected: u64) -> Result<(), Refusal> {
    let generation = ConsentLeaseGenerationV1::new(expected).ok_or(Refusal::LeaseFenced)?;
    store.conn.execute_batch("BEGIN").ok();
    let result = require_current_consent_lease_generation(&store.conn, generation);
    store.conn.execute_batch("ROLLBACK").ok();
    result
}

#[test]
fn the_fence_accepts_exactly_the_stored_generation() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = store_with_empty_journal()?;
    let lease = fixture.acquire(&store)?;
    let current = lease.generation().get();
    assert_eq!(fenced(&store, current), Ok(()));
    assert_eq!(fenced(&store, current + 1), Err(Refusal::LeaseFenced));
    assert_eq!(fenced(&store, u64::MAX), Err(Refusal::LeaseFenced));
    drop(lease);
    assert_eq!(fixture.generation(&store), Ok(2));
    assert_eq!(fenced(&store, current), Err(Refusal::LeaseFenced));
    assert_eq!(fenced(&store, 2), Ok(()));
    Ok(())
}

#[test]
fn the_fence_needs_a_transaction() -> TestResult {
    let fixture = Fixture::new(true)?;
    let store = SqliteStore::open_in_memory()?;
    let lease = fixture.acquire(&store)?;
    assert_eq!(
        require_current_consent_lease_generation(&store.conn, lease.generation()),
        Err(Refusal::NotInTransaction)
    );
    Ok(())
}

#[test]
fn the_fence_refuses_a_missing_corrupt_or_unreadable_row() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    assert_eq!(fenced(&store, 1), Err(Refusal::LeaseFenced));
    insert_unchecked(&store, "(1, 2, 1)")?;
    assert_eq!(fenced(&store, 1), Err(Refusal::LeaseFenced));
    store
        .conn
        .execute_batch("DROP TABLE gateway_consent_lease")?;
    assert_eq!(fenced(&store, 1), Err(Refusal::LeaseFenced));
    Ok(())
}

#[test]
fn the_real_table_rejects_a_zero_generation_and_a_foreign_format() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    for values in [
        "(1, 1, 0)",
        "(1, 2, 1)",
        "(2, 1, 1)",
        "(1, 1, -1)",
        "(1, 'x', 1)",
        "(1, 1, 'x')",
        "('x', 1, 1)",
    ] {
        assert!(
            store
                .conn
                .execute_batch(&format!(
                    "INSERT INTO gateway_consent_lease (singleton, format_version, generation)
                     VALUES {values}"
                ))
                .is_err(),
            "{values}"
        );
    }
    assert_eq!(stored(&store)?, Vec::new());
    Ok(())
}
