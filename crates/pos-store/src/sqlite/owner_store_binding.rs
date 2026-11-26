#![cfg(any(test, feature = "test-support"))]
//! Native half of the ADR-123 qualified owner-store binding (Redmine #1547).
//!
//! `SqliteStore` keeps its connection private to this module tree, so the
//! qualified constructor, the guarded operation entry and managed disposal
//! live here; the filesystem screening, the diagnostic parser and the
//! process-lifetime context live in [`crate::owner_store_binding`].
//!
//! The native connection is owned through `ManuallyDrop` and is never closed
//! by a destructor (ADR-123 §1, §6): only [`QualifiedSqliteStoreV1::close`]
//! closes it, under admission, the interlock and a witness recheck. A handle
//! dropped without it, or a close that cannot be proved safe, retains the
//! connection and its witnesses until process exit and keeps the context's
//! native slot occupied.

use std::fmt;
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{GatewayModeBindingErrorV1, GatewayModeBindingPortV1, GatewayModeBindingRecordV1};
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};
use rustix::fd::OwnedFd;

use super::SqliteStore;
use crate::owner_store_admission::OwnerStoreOperationV1;
use crate::owner_store_binding::{
    OwnerStoreBindingErrorV1, OwnerStoreContextV1, OwnerStoreWitnessesV1,
};
use crate::owner_store_interlock::OwnerStoreFileInterlockV1;

/// The native string-length bound while the fixed diagnostic runs (ADR-123 §5).
const DIAGNOSTIC_LENGTH_LIMIT: i32 = 65_536;
const FILESTAT_SQL: &str = "SELECT sqlite_filestat('main')";

#[cfg(test)]
thread_local! {
    /// Test-only seam: the diagnostic's length-limit restore fails.
    static FAIL_LIMIT_RESTORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only seam: the managed `Connection::close` fails.
    static FAIL_MANAGED_CLOSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only seam: the guarded `COMMIT` or `ROLLBACK` fails.
    static FAIL_TRANSACTION_FINISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The qualified owner store: one managed native connection to an installed
/// store whose main file `SQLite` was proved to hold (ADR-123 §5).
///
/// It has no conversion from or to a raw handle, connection, integer pair or
/// trait object, and no `Deref` to a connection.
pub struct QualifiedSqliteStoreV1 {
    context: Arc<OwnerStoreContextV1>,
    directory: PathBuf,
    main_basename: String,
    file_id: SubjectStoreFileIdV1,
    native: ManuallyDrop<NativeOwnerV1>,
}

/// Everything retained with the native connection.
struct NativeOwnerV1 {
    store: SqliteStore,
    witnesses: OwnerStoreWitnessesV1,
    native_witnesses: [OwnedFd; 3],
}

/// The borrowed binding that exists only inside a guarded operation.
pub struct ProtectedStoreFileBindingV1<'store> {
    store: &'store mut SqliteStore,
    file_id: SubjectStoreFileIdV1,
}

/// How a failed step ends: `Refuse` proved native closure or never opened
/// `SQLite`; `Retain` keeps the native owner and quarantines.
enum StepV1 {
    Refuse(OwnerStoreBindingErrorV1),
    Retain,
}

impl StepV1 {
    fn release_refused_slot(&self, context: &OwnerStoreContextV1) {
        if let Self::Refuse(_) = self {
            context.release_native_slot();
        }
    }
}

impl fmt::Debug for QualifiedSqliteStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedSqliteStoreV1")
            .field("file_id", &self.file_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ProtectedStoreFileBindingV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedStoreFileBindingV1")
            .field("file_id", &self.file_id)
            .finish_non_exhaustive()
    }
}

impl ProtectedStoreFileBindingV1<'_> {
    /// The proven E16 identity of the bound main file. It grants no key,
    /// consent or append authority.
    #[must_use]
    pub const fn store_file_id(&self) -> SubjectStoreFileIdV1 {
        self.file_id
    }

    /// The bound store inside the guarded transaction.
    pub(super) const fn store(&mut self) -> &mut SqliteStore {
        &mut *self.store
    }
}

impl QualifiedSqliteStoreV1 {
    /// Bind the installed store `main_basename` in an explicit private test
    /// database directory (ADR-123 §4–§6, ADR-110 E20 LC1 step 5).
    ///
    /// `pre_screen_key` is the main-file candidate the caller pre-screened
    /// and keyed its in-child Gateway mode lock on. The order is: shared
    /// admission, the context's native slot, the filesystem interlock,
    /// screening and empty-companion provisioning, a read-write no-follow
    /// open on the `unix` VFS with `busy_timeout` 0, a WAL and UTF-8 check,
    /// then one setup `BEGIN IMMEDIATE` holding the native proof, schema
    /// validation (the store is never initialized) and the LC3 mode attach:
    /// `load_mode_binding`, then `attach_mode_binding` to that record's
    /// profile. The proven identity must equal `pre_screen_key`.
    ///
    /// # Errors
    /// Returns `Admission` before any lower lock. A full native slot, an
    /// unavailable interlock, a refused screening or open, a failed check, a
    /// busy setup transaction, a failed schema validation or an identity that
    /// differs from `pre_screen_key` return `Unavailable`; an unbound or
    /// mismatched mode binding returns `ModeBinding`. In those cases the
    /// connection, if opened, was closed under the interlock after a witness
    /// recheck. A failed native proof, a failed length-limit restore or an
    /// unproved close returns `Quarantined`.
    pub fn open(
        context: Arc<OwnerStoreContextV1>,
        test_database_directory: &Path,
        main_basename: &str,
        pre_screen_key: SubjectStoreFileIdV1,
    ) -> Result<Self, OwnerStoreBindingErrorV1> {
        let admitted = context
            .admission()
            .try_enter()
            .map_err(OwnerStoreBindingErrorV1::Admission)?;
        let outcome = if context.claim_native_slot() {
            OwnerStoreFileInterlockV1::try_acquire(
                &admitted,
                test_database_directory,
                main_basename,
            )
            .map_err(|_| StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
            .and_then(|_interlock| setup(test_database_directory, main_basename, pre_screen_key))
            .inspect_err(|step| step.release_refused_slot(&context))
        } else {
            Err(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        };
        conclude(admitted, outcome).map(|native| Self {
            file_id: native.witnesses.store_file_id(),
            context,
            directory: test_database_directory.to_path_buf(),
            main_basename: main_basename.to_owned(),
            native: ManuallyDrop::new(native),
        })
    }

    /// The proven E16 identity of the bound main file,
    /// `SubjectStoreFileIdV1::Linux`.
    #[must_use]
    pub const fn store_file_id(&self) -> SubjectStoreFileIdV1 {
        self.file_id
    }

    /// Run one guarded operation in one `BEGIN IMMEDIATE` (ADR-123 §6).
    ///
    /// Shared admission, the filesystem interlock and a recheck of every
    /// retained witness precede the transaction; a fresh native proof follows
    /// it before `operation` runs. `Ok` from `operation` commits and `Err`
    /// rolls back; either is returned inside `Ok`.
    ///
    /// # Errors
    /// Returns `Admission` before any lower lock, `Unavailable` when the
    /// interlock or the transaction is busy, and `Quarantined` when a witness
    /// changed, the native proof failed or the transaction could not finish.
    pub fn guarded<T, E>(
        &mut self,
        operation: impl FnOnce(&mut ProtectedStoreFileBindingV1<'_>) -> Result<T, E>,
    ) -> Result<Result<T, E>, OwnerStoreBindingErrorV1> {
        let context = Arc::clone(&self.context);
        let admitted = context
            .admission()
            .try_enter()
            .map_err(OwnerStoreBindingErrorV1::Admission)?;
        let file_id = self.file_id;
        let native = &mut *self.native;
        let outcome =
            OwnerStoreFileInterlockV1::try_acquire(&admitted, &self.directory, &self.main_basename)
                .map_err(|_| StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
                .and_then(|_interlock| run_guarded(native, file_id, operation));
        conclude(admitted, outcome)
    }

    /// Close the native connection under admission and the interlock after
    /// a recheck of every retained witness, then release the native slot.
    ///
    /// # Errors
    /// Returns `Admission` without touching the connection, which stays
    /// retained. A busy interlock, a changed witness or a failed close
    /// returns `Quarantined` and retains the connection until process exit.
    pub fn close(self) -> Result<(), OwnerStoreBindingErrorV1> {
        let Self {
            context,
            directory,
            main_basename,
            native,
            ..
        } = self;
        let admitted = context
            .admission()
            .try_enter()
            .map_err(OwnerStoreBindingErrorV1::Admission)?;
        let outcome = OwnerStoreFileInterlockV1::try_acquire(&admitted, &directory, &main_basename)
            .map_err(|_| StepV1::Retain)
            .and_then(|_interlock| {
                let NativeOwnerV1 {
                    store,
                    witnesses,
                    native_witnesses,
                } = ManuallyDrop::into_inner(native);
                dispose(store, witnesses, native_witnesses)
                    .then(|| context.release_native_slot())
                    .ok_or(StepV1::Retain)
            });
        conclude(admitted, outcome)
    }
}

/// Finish an admitted step: proved outcomes restore idle admission, a
/// retained native owner quarantines it.
fn conclude<T>(
    admitted: OwnerStoreOperationV1<'_>,
    outcome: Result<T, StepV1>,
) -> Result<T, OwnerStoreBindingErrorV1> {
    match outcome {
        Ok(value) => {
            admitted.complete_cleanly();
            Ok(value)
        }
        Err(StepV1::Refuse(error)) => {
            admitted.complete_cleanly();
            Err(error)
        }
        Err(StepV1::Retain) => {
            drop(admitted);
            Err(OwnerStoreBindingErrorV1::Quarantined)
        }
    }
}

/// Screen, provision, open and bind under the held interlock.
fn setup(
    directory: &Path,
    main_basename: &str,
    pre_screen_key: SubjectStoreFileIdV1,
) -> Result<NativeOwnerV1, StepV1> {
    OwnerStoreWitnessesV1::screen(directory, main_basename)
        .and_then(|witnesses| {
            witnesses
                .sqlite_path(directory, main_basename)
                .and_then(|path| open_native(&path))
                .map(|store| (store, witnesses))
        })
        .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|(store, witnesses)| bind_native(store, witnesses, pre_screen_key))
}

/// Open the screened main file: read-write, no create, no URI, no symlink,
/// the standard `unix` VFS and no reservation connection.
fn open_native(path: &Path) -> Option<SqliteStore> {
    Connection::open_with_flags_and_vfs(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        c"unix",
    )
    .ok()
    .map(|conn| {
        conn.set_prepared_statement_cache_capacity(super::SQLITE_STATEMENT_CACHE_CAPACITY);
        SqliteStore::with_connection(conn, None, Box::new(pos_crypto::chain::Blake3Hasher), 0)
    })
}

/// Configure, prove and attach inside the setup transaction; dispose of the
/// connection on any refusal.
fn bind_native(
    mut store: SqliteStore,
    witnesses: OwnerStoreWitnessesV1,
    pre_screen_key: SubjectStoreFileIdV1,
) -> Result<NativeOwnerV1, StepV1> {
    let file_id = witnesses.store_file_id();
    let bound = configure(&store.conn)
        .then_some(())
        .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|()| begin(&store.conn))
        .and_then(|()| prove_in_transaction(&store.conn, &witnesses))
        .and_then(|native_witnesses| {
            let attached = validate_and_attach(&mut ProtectedStoreFileBindingV1 {
                store: &mut store,
                file_id,
            });
            finish(&store.conn, attached.is_ok())
                .and_then(|()| attached.map_err(StepV1::Refuse))
                .map(|()| native_witnesses)
        })
        .and_then(|native_witnesses| {
            (file_id == pre_screen_key)
                .then_some(native_witnesses)
                .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        });
    match bound {
        Ok(native_witnesses) => Ok(NativeOwnerV1 {
            store,
            witnesses,
            native_witnesses,
        }),
        Err(StepV1::Refuse(error)) => Err(if dispose(store, witnesses, ()) {
            StepV1::Refuse(error)
        } else {
            StepV1::Retain
        }),
        Err(StepV1::Retain) => {
            retain((store, witnesses));
            Err(StepV1::Retain)
        }
    }
}

/// `busy_timeout` 0, then require the existing WAL journal mode (never
/// changed to admit) and UTF-8.
fn configure(conn: &Connection) -> bool {
    conn.busy_timeout(Duration::ZERO).is_ok()
        && conn
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .is_ok_and(|mode| mode == "wal")
        && SqliteStore::require_utf8_encoding(conn).is_ok()
}

fn begin(conn: &Connection) -> Result<(), StepV1> {
    conn.execute_batch(super::begin_immediate_sql())
        .map_err(|_| StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
}

/// Capture and prove the native diagnostic inside the open transaction. A
/// failure rolls back and retains: the native owner is uncertain.
fn prove_in_transaction(
    conn: &Connection,
    witnesses: &OwnerStoreWitnessesV1,
) -> Result<[OwnedFd; 3], StepV1> {
    native_diagnostic(conn)
        .ok()
        .and_then(|filestat| witnesses.prove(&filestat))
        .ok_or_else(|| {
            drop(conn.execute_batch("ROLLBACK"));
            StepV1::Retain
        })
}

/// Run `sqlite_filestat('main')` under a 65,536-byte native length limit and
/// restore the previous limit before any other SQL. A failed restore
/// dominates the query result.
fn native_diagnostic(conn: &Connection) -> rusqlite::Result<String> {
    conn.limit(Limit::SQLITE_LIMIT_LENGTH).and_then(|saved| {
        conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, DIAGNOSTIC_LENGTH_LIMIT)
            .and_then(|_| {
                let captured = conn.query_row(FILESTAT_SQL, [], |row| row.get::<_, String>(0));
                restore_limit(conn, saved).and(captured)
            })
    })
}

fn restore_limit(conn: &Connection, saved: i32) -> rusqlite::Result<()> {
    #[cfg(test)]
    if FAIL_LIMIT_RESTORE.with(std::cell::Cell::get) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, saved)
        .map(|_| ())
}

/// Validate the existing schema without initializing it (ADR-123 §4), then
/// attach the persisted mode binding to its own profile (ADR-110 E20 LC3).
fn validate_and_attach(
    binding: &mut ProtectedStoreFileBindingV1<'_>,
) -> Result<(), OwnerStoreBindingErrorV1> {
    binding
        .store()
        .finish_open(false, true)
        .map_err(|_| OwnerStoreBindingErrorV1::Unavailable)
        .and_then(|()| {
            attach_owner_mode(binding.store())
                .map(|_| ())
                .map_err(OwnerStoreBindingErrorV1::ModeBinding)
        })
}

fn attach_owner_mode(
    store: &mut SqliteStore,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    store
        .load_mode_binding()
        .and_then(|record| record.ok_or(GatewayModeBindingErrorV1::Unbound))
        .and_then(|record| store.attach_mode_binding(record.profile()))
}

/// The guarded body under the held interlock.
fn run_guarded<T, E>(
    native: &mut NativeOwnerV1,
    file_id: SubjectStoreFileIdV1,
    operation: impl FnOnce(&mut ProtectedStoreFileBindingV1<'_>) -> Result<T, E>,
) -> Result<Result<T, E>, StepV1> {
    native
        .witnesses
        .recheck()
        .then_some(())
        .ok_or(StepV1::Retain)
        .and_then(|()| begin(&native.store.conn))
        .and_then(|()| prove_in_transaction(&native.store.conn, &native.witnesses).map(drop))
        .and_then(|()| {
            let result = operation(&mut ProtectedStoreFileBindingV1 {
                store: &mut native.store,
                file_id,
            });
            finish(&native.store.conn, result.is_ok()).map(|()| result)
        })
}

/// `COMMIT` or `ROLLBACK`; an unproved finish retains and quarantines.
fn finish(conn: &Connection, commit: bool) -> Result<(), StepV1> {
    finish_sql(conn, if commit { "COMMIT" } else { "ROLLBACK" }).map_err(|_| StepV1::Retain)
}

fn finish_sql(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    #[cfg(test)]
    if FAIL_TRANSACTION_FINISH.with(std::cell::Cell::get) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    conn.execute_batch(sql)
}

/// Managed close (ADR-123 §6): close only after the retained witnesses
/// recheck; otherwise, or when the close fails, retain the connection, the
/// witnesses and `retained` until process exit. Returns whether it closed.
fn dispose<R>(store: SqliteStore, witnesses: OwnerStoreWitnessesV1, retained: R) -> bool {
    let safe = witnesses.recheck();
    let SqliteStore { conn, .. } = store;
    managed_close(conn, safe)
        .map_err(|failed| retain((failed, witnesses, retained)))
        .is_ok()
}

/// A failed close returns the still-open connection, boxed, so it stays
/// owned.
fn managed_close(conn: Connection, safe: bool) -> Result<(), Box<(Connection, rusqlite::Error)>> {
    #[cfg(test)]
    if FAIL_MANAGED_CLOSE.with(std::cell::Cell::get) {
        return Err(Box::new((conn, rusqlite::Error::InvalidQuery)));
    }
    if safe {
        conn.close().map_err(Box::new)
    } else {
        Err(Box::new((conn, rusqlite::Error::InvalidQuery)))
    }
}

/// Retain a native owner until process exit: no destructor runs, so
/// `SQLite` never checkpoints or deletes a companion outside the interlock.
const fn retain<T>(value: T) -> ManuallyDrop<T> {
    ManuallyDrop::new(value)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::Cell;
    use std::num::NonZeroU64;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::thread::LocalKey;

    use pos_core::{GatewayModeBindingHostV1, GatewayModeProfileRefV1};
    use pos_crypto::subject_field_read::SubjectFieldOwnerReadErrorV1;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::owner_store_admission::OwnerStoreAdmissionV1;
    use crate::owner_store_installation::install_owner_store_namespace_v1;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const MAIN: &str = "store.db";
    const ACTIVE: OwnerStoreBindingErrorV1 =
        OwnerStoreBindingErrorV1::Admission(SubjectFieldOwnerReadErrorV1::OperationActive);
    const QUARANTINED: OwnerStoreBindingErrorV1 =
        OwnerStoreBindingErrorV1::Admission(SubjectFieldOwnerReadErrorV1::ContextQuarantined);

    struct Fixture {
        directory: tempfile::TempDir,
        key: SubjectStoreFileIdV1,
        other_key: SubjectStoreFileIdV1,
        context: Arc<OwnerStoreContextV1>,
    }

    impl Fixture {
        fn open(&self) -> Result<QualifiedSqliteStoreV1, OwnerStoreBindingErrorV1> {
            self.open_with(self.key)
        }

        fn open_with(
            &self,
            key: SubjectStoreFileIdV1,
        ) -> Result<QualifiedSqliteStoreV1, OwnerStoreBindingErrorV1> {
            QualifiedSqliteStoreV1::open(
                Arc::clone(&self.context),
                self.directory.path(),
                MAIN,
                key,
            )
        }

        fn path(&self, suffix: &str) -> PathBuf {
            self.directory.path().join(format!("{MAIN}{suffix}"))
        }

        /// A second, unmanaged connection that holds the main file open.
        fn raw_reader(&self) -> TestResult<Connection> {
            let conn = Connection::open(self.path(""))?;
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })?;
            Ok(conn)
        }

        /// Replace the WAL entry with a new private file of the same name.
        fn replace_wal(&self) -> TestResult {
            std::fs::rename(self.path("-wal"), self.path("-moved"))?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.path("-wal"))?;
            Ok(())
        }
    }

    fn profile() -> TestResult<GatewayModeProfileRefV1> {
        let digest = Sha256::digest(b"pigloros owner-store binding test profile");
        Ok(GatewayModeProfileRefV1::try_new(
            "owner-store-binding-test",
            std::array::from_fn(|index| digest[index]),
        )?)
    }

    fn private_directory() -> std::io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
    }

    /// Make the closed store private, install it and record its identity.
    fn install(directory: tempfile::TempDir) -> TestResult<Fixture> {
        let path = directory.path().join(MAIN);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        install_owner_store_namespace_v1(directory.path(), MAIN)?;
        let metadata = std::fs::metadata(&path)?;
        Ok(Fixture {
            key: SubjectStoreFileIdV1::Linux {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            other_key: SubjectStoreFileIdV1::Linux {
                device: metadata.dev(),
                inode: metadata.ino().wrapping_add(1),
            },
            directory,
            context: Arc::new(OwnerStoreContextV1::default()),
        })
    }

    /// An ordinary store, optionally bound to the test profile, installed.
    fn installed(bind: bool) -> TestResult<Fixture> {
        let directory = private_directory()?;
        {
            let path = directory.path().join(MAIN);
            let mut store = SqliteStore::open(path.to_str().ok_or("path")?)?;
            if bind {
                store.bind_empty_store_mode(
                    GatewayModeBindingHostV1::new().authorize_bind(profile()?),
                )?;
            }
        }
        install(directory)
    }

    /// A WAL database that is not a store: it has no store schema.
    fn installed_foreign() -> TestResult<Fixture> {
        let directory = private_directory()?;
        Connection::open(directory.path().join(MAIN))?
            .execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE unrelated (value INTEGER);")?;
        install(directory)
    }

    /// A complete bound store whose text encoding is UTF-16.
    fn installed_utf16() -> TestResult<Fixture> {
        let directory = private_directory()?;
        {
            let conn = Connection::open(directory.path().join(MAIN))?;
            conn.execute_batch("PRAGMA encoding = 'UTF-16le'")?;
            let mut store = SqliteStore::with_connection(
                conn,
                None,
                Box::new(pos_crypto::chain::Blake3Hasher),
                0,
            );
            store.finish_open(true, false)?;
            store.bind_empty_store_mode(
                GatewayModeBindingHostV1::new().authorize_bind(profile()?),
            )?;
        }
        install(directory)
    }

    fn with_seam<T>(seam: &'static LocalKey<Cell<bool>>, action: impl FnOnce() -> T) -> T {
        seam.with(|flag| flag.set(true));
        let result = action();
        seam.with(|flag| flag.set(false));
        result
    }

    fn table_names(conn: &Connection) -> rusqlite::Result<Vec<String>> {
        conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get(0))
                    .and_then(Iterator::collect::<rusqlite::Result<Vec<String>>>)
            })
    }

    #[test]
    fn binds_proves_guards_and_closes_an_installed_store() -> TestResult {
        let fixture = installed(true)?;
        assert!(!fixture.path("-wal").exists());
        assert!(!fixture.path("-shm").exists());
        let mut store = fixture.open()?;
        assert_eq!(store.store_file_id(), fixture.key);
        assert!(format!("{store:?}").contains("QualifiedSqliteStoreV1"));
        for suffix in ["-wal", "-shm"] {
            let metadata = std::fs::symlink_metadata(fixture.path(suffix))?;
            assert!(metadata.is_file());
            assert_eq!(metadata.mode() & 0o7777, 0o600);
        }
        let default_length = Connection::open_in_memory()?.limit(Limit::SQLITE_LIMIT_LENGTH)?;
        let committed = store.guarded(|binding| {
            assert_eq!(binding.store_file_id(), fixture.key);
            assert!(format!("{binding:?}").contains("ProtectedStoreFileBindingV1"));
            let store = binding.store();
            assert_eq!(store.mode_binding_epoch, NonZeroU64::new(1));
            assert!(!store.conn.is_autocommit());
            assert_eq!(
                store.conn.limit(Limit::SQLITE_LIMIT_LENGTH).ok(),
                Some(default_length)
            );
            assert_eq!(
                store
                    .conn
                    .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                    .ok(),
                Some(0)
            );
            store
                .conn
                .execute_batch("CREATE TABLE committed_probe (value INTEGER)")
                .map(|()| 7)
        })?;
        assert_eq!(committed?, 7);
        let rolled_back = store.guarded(|binding| {
            binding
                .store()
                .conn
                .execute_batch("CREATE TABLE rolled_back_probe (value INTEGER)")
                .and(Err::<(), _>(rusqlite::Error::InvalidQuery))
        })?;
        assert!(rolled_back.is_err());
        let tables = store.guarded(|binding| table_names(&binding.store().conn))??;
        assert!(tables.iter().any(|name| name == "committed_probe"));
        assert!(!tables.iter().any(|name| name == "rolled_back_probe"));
        store.close()?;
        let reopened = fixture.open()?;
        assert_eq!(reopened.store_file_id(), fixture.key);
        reopened.close()?;
        Ok(())
    }

    #[test]
    fn one_native_connection_per_context_and_admission_refuses_first() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        let active = fixture
            .context
            .admission()
            .try_enter()
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(fixture.open().err(), Some(ACTIVE));
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(ACTIVE));
        assert_eq!(store.close().err(), Some(ACTIVE));
        active.complete_cleanly();
        // The refused close retained the connection, so the slot stays full.
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn an_unbound_store_refuses_owner_readiness_and_closes() -> TestResult {
        let fixture = installed(false)?;
        let unbound = OwnerStoreBindingErrorV1::ModeBinding(GatewayModeBindingErrorV1::Unbound);
        assert_eq!(fixture.open().err(), Some(unbound));
        assert_eq!(fixture.open().err(), Some(unbound));
        Ok(())
    }

    #[test]
    fn a_proven_identity_other_than_the_pre_screen_key_is_disposed() -> TestResult {
        let fixture = installed(true)?;
        assert_eq!(
            fixture.open_with(fixture.other_key).err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        fixture.open()?.close()?;
        Ok(())
    }

    #[test]
    fn a_failed_check_or_validation_refuses_after_closing_the_connection() -> TestResult {
        for fixture in [installed_foreign()?, installed_utf16()?] {
            assert_eq!(
                fixture.open().err(),
                Some(OwnerStoreBindingErrorV1::Unavailable)
            );
            assert_eq!(
                fixture.open().err(),
                Some(OwnerStoreBindingErrorV1::Unavailable)
            );
        }
        Ok(())
    }

    #[test]
    fn a_busy_setup_transaction_refuses_and_closes() -> TestResult {
        let fixture = installed(true)?;
        let busy = with_seam(&super::super::FAIL_BEGIN_IMMEDIATE, || fixture.open());
        assert_eq!(busy.err(), Some(OwnerStoreBindingErrorV1::Unavailable));
        fixture.open()?.close()?;
        Ok(())
    }

    #[test]
    fn a_failed_native_proof_at_setup_retains_and_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let _reader = fixture.raw_reader()?;
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Quarantined)
        );
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_failed_limit_restore_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let restored = with_seam(&FAIL_LIMIT_RESTORE, || fixture.open());
        assert_eq!(restored.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_failed_setup_disposal_retains_and_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let disposed = with_seam(&FAIL_MANAGED_CLOSE, || fixture.open_with(fixture.other_key));
        assert_eq!(disposed.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_guarded_operation_refuses_a_busy_interlock_or_transaction_and_stays_idle() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        let busy = with_seam(&super::super::FAIL_BEGIN_IMMEDIATE, || {
            store.guarded(|_| Ok::<(), ()>(()))
        });
        assert_eq!(busy.err(), Some(OwnerStoreBindingErrorV1::Unavailable));
        let other = OwnerStoreAdmissionV1::new();
        let operation = other.try_enter().map_err(|error| format!("{error:?}"))?;
        let interlock =
            OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.directory.path(), MAIN)?;
        assert_eq!(
            store.guarded(|_| Ok::<(), ()>(())).err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        let other_context = Arc::new(OwnerStoreContextV1::default());
        assert_eq!(
            QualifiedSqliteStoreV1::open(
                Arc::clone(&other_context),
                fixture.directory.path(),
                MAIN,
                fixture.key
            )
            .err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        assert!(other_context.claim_native_slot());
        drop(interlock);
        assert_eq!(store.guarded(|_| Ok::<(), ()>(()))?, Ok(()));
        let interlock =
            OwnerStoreFileInterlockV1::try_acquire(&operation, fixture.directory.path(), MAIN)?;
        assert_eq!(
            store.close().err(),
            Some(OwnerStoreBindingErrorV1::Quarantined)
        );
        drop(interlock);
        operation.complete_cleanly();
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_changed_witness_quarantines_a_guarded_operation() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        fixture.replace_wal()?;
        assert_eq!(
            store.guarded(|_| Ok::<(), ()>(())).err(),
            Some(OwnerStoreBindingErrorV1::Quarantined)
        );
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(QUARANTINED));
        assert_eq!(store.close().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_changed_witness_retains_the_connection_at_close() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        fixture.replace_wal()?;
        assert_eq!(
            store.close().err(),
            Some(OwnerStoreBindingErrorV1::Quarantined)
        );
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_failed_fresh_proof_quarantines_a_guarded_operation() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        let _reader = fixture.raw_reader()?;
        assert_eq!(
            store.guarded(|_| Ok::<(), ()>(())).err(),
            Some(OwnerStoreBindingErrorV1::Quarantined)
        );
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn an_unproved_transaction_finish_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        let finished = with_seam(&FAIL_TRANSACTION_FINISH, || {
            store.guarded(|_| Ok::<(), ()>(()))
        });
        assert_eq!(finished.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(QUARANTINED));
        Ok(())
    }

    #[test]
    fn a_failed_managed_close_retains_and_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        let closed = with_seam(&FAIL_MANAGED_CLOSE, || store.close());
        assert_eq!(closed.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }
}
