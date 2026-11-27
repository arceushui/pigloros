#![cfg(any(test, feature = "test-support"))]
//! Native half of the ADR-123 qualified owner-store binding (Redmine #1547).
//!
//! `SqliteStore` keeps its connection private to this module tree, so the
//! qualified constructor, the guarded operation entry and managed disposal
//! live here; the filesystem screening, the diagnostic parser and the
//! process-lifetime context live in [`crate::owner_store_binding`].
//!
//! The native connection is owned through `ManuallyDrop` from the moment it
//! is opened and is never closed by a destructor, also while a panic unwinds
//! (ADR-123 §1, §6): only [`QualifiedSqliteStoreV1::close`] closes it, under
//! admission, the interlock and a witness recheck. A handle dropped without
//! it, a panic before a proved close, or a close that cannot be proved safe
//! retains the connection and its witnesses until process exit and keeps the
//! context's native slot occupied.
//!
//! The main file's identity is claimed in a process-wide registry from the
//! moment its connection opens: a second context, wrapper or alias is refused
//! as `Unavailable` before any native open while the connection is live or
//! retained (ADR-123 §1: one connection per process). Only a proved close or a
//! proved refusal disposal releases the claim, so a retained or dropped handle
//! keeps its file refused for the rest of the process. A panic during setup
//! leaves the retained connection's `BEGIN IMMEDIATE` write transaction open
//! until process exit: it keeps the `SQLite` write lock and blocks other
//! processes' writers, which is the retention ADR-123 §6 intends.
//!
//! The canonical directory path `SQLite` remembered at open must keep naming
//! the retained directory while the handle lives: `SQLite` removes `-wal` and
//! `-shm` by that path, so every guarded operation and the close require the
//! interlock (taken through the retained descriptor) and then that the
//! canonical path still names that directory, whatever the caller's own path
//! (possibly a symlink) names now; otherwise the context is quarantined and
//! the connection and claim are retained (ADR-123 §6). The open takes one
//! interlock on the caller's path, screens, proves the interlock's directory
//! object is the screened one and keeps that same interlock through the
//! recheck, the claim and the native open (ADR-123 §4).
//!
//! A failed diagnostic query (`sqlite_filestat` missing, over the length
//! limit or malformed) always retains and quarantines, never a clean
//! `Unavailable` with disposal: the connection's native owner is uncertain.
//! This is conservative and reachable only in test-support builds.
//!
//! A proven identity that differs from the caller's pre-screen key returns
//! the fixed `Unavailable` before the schema or mode binding is touched
//! (ADR-123 §6 fixes plain `Unavailable` only for lease-free writers). The
//! mapping for a lease holder is undefined here: ADR-137 L5 step 5 requires
//! `LeaseIdentityMismatch`, but `Unavailable` is also returned for a busy
//! interlock or transaction, an unsafe or non-WAL file, a schema failure and
//! a retained identity, so `serve` cannot tell a mismatch from them. An
//! ADR-123/ADR-137 erratum that adds a distinguishable mismatch signal is
//! needed before activation in #1438.

use std::fmt;
#[cfg(not(test))]
use std::mem::ManuallyDrop as Retained;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{GatewayModeBindingErrorV1, GatewayModeBindingPortV1, GatewayModeBindingRecordV1};
use pos_crypto::subject_field_read::SubjectFieldOwnerReadErrorV1;
use pos_crypto::subject_nonce_ledger::SubjectStoreFileIdV1;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};
use rustix::fd::OwnedFd;

use super::SqliteStore;
use crate::owner_store_admission::OwnerStoreOperationV1;
use crate::owner_store_binding::{
    claim_identity, is_claimed, release_identity, OwnerStoreBindingErrorV1, OwnerStoreContextV1,
    OwnerStoreWitnessesV1,
};
use crate::owner_store_interlock::OwnerStoreFileInterlockV1;

#[cfg(test)]
use self::retained::Retained;

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
    /// Test-only seam: setup panics after the connection opened.
    static PANIC_SETUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only seam: managed disposal panics before the connection closes.
    static PANIC_DISPOSE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Test-only seam: runs once after the interlock, before the screening.
    static AFTER_INTERLOCK: HookSlot =
        const { std::cell::RefCell::new(None) };
    /// Test-only seam: runs once after the screening, before the identity proof.
    static AFTER_SCREEN: HookSlot =
        const { std::cell::RefCell::new(None) };
    /// Test-only seam: how many native opens were attempted on this thread.
    static NATIVE_OPENS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
type HookSlot = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
fn run_hook(slot: &'static std::thread::LocalKey<HookSlot>) {
    if let Some(hook) = slot.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

/// The qualified owner store: one managed native connection to an installed
/// store whose main file `SQLite` was proved to hold (ADR-123 §5).
///
/// It has no conversion from or to a raw handle, connection, integer pair or
/// trait object, and no `Deref` to a connection.
pub struct QualifiedSqliteStoreV1 {
    context: Arc<OwnerStoreContextV1>,
    main_basename: String,
    file_id: SubjectStoreFileIdV1,
    native: Retained<NativeOwnerV1>,
}

/// Everything retained with the native connection. The store is never
/// dropped: only managed disposal takes the connection out.
struct NativeOwnerV1 {
    /// The canonical directory `SQLite` remembered at open. Every later
    /// interlock requires it to still name the retained directory (ADR-123
    /// §6): `SQLite` deletes `-wal` and `-shm` by the names it remembered.
    canonical_directory: PathBuf,
    store: Retained<SqliteStore>,
    witnesses: OwnerStoreWitnessesV1,
    native_witnesses: [OwnedFd; 3],
}

/// Why [`QualifiedSqliteStoreV1::close`] did not close the connection.
#[derive(Debug, thiserror::Error)]
pub enum OwnerStoreCloseErrorV1 {
    /// Shared admission refused before any lower lock. The connection was not
    /// touched and nothing was quarantined by this call: the handle is
    /// returned so disposal can be retried.
    #[error("owner store close refused by admission")]
    Refused {
        /// The admission refusal.
        error: SubjectFieldOwnerReadErrorV1,
        /// The untouched handle.
        store: Box<QualifiedSqliteStoreV1>,
    },
    /// A busy interlock, a changed witness or a failed close. The connection
    /// and witnesses stay retained until process exit and the context is
    /// quarantined (ADR-123 §6).
    #[error("protected owner store close quarantined")]
    Quarantined,
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
    /// screening and empty-companion provisioning, the proof that the
    /// interlock's directory and main file are the screened ones, a read-write
    /// no-follow open on the `unix` VFS with `busy_timeout` 0, a WAL and UTF-8 check,
    /// then one setup `BEGIN IMMEDIATE` holding the native proof, schema
    /// validation (the store is never initialized) and the LC3 mode attach:
    /// `load_mode_binding`, then `attach_mode_binding` to that record's
    /// profile. The proven identity must equal `pre_screen_key`; that is
    /// checked right after the proof, before the schema or the mode binding.
    ///
    /// # Errors
    /// Returns `Admission` before any lower lock. A full native slot, an
    /// unavailable interlock, a refused screening or open, a failed check, a
    /// busy setup transaction, a failed schema validation or an identity that
    /// differs from `pre_screen_key` return `Unavailable`; an unbound or
    /// mismatched mode binding returns `ModeBinding`. In those cases the
    /// connection, if opened, was closed under the interlock after a witness
    /// recheck. A failed native proof, a failed length-limit restore or an
    /// unproved close returns `Quarantined`. A main file whose connection a
    /// quarantined or dropped handle retained, or that a live handle holds, is
    /// `Unavailable` to every other context in this process before any native
    /// open, and the live handle is unaffected.
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
            bind(
                &admitted,
                test_database_directory,
                main_basename,
                pre_screen_key,
            )
            .inspect_err(|step| step.release_refused_slot(&context))
        } else {
            Err(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        };
        conclude(admitted, outcome).map(|native| Self {
            file_id: native.witnesses.store_file_id(),
            context,
            main_basename: main_basename.to_owned(),
            native: Retained::new(native),
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
    /// Shared admission, the filesystem interlock (taken through the retained
    /// directory descriptor, so a swapped path cannot redirect it) and a
    /// recheck of every retained witness precede the transaction; a fresh native proof follows
    /// it before `operation` runs. `Ok` from `operation` commits and `Err`
    /// rolls back; either is returned inside `Ok`. A panic in `operation`
    /// leaves the transaction open and the context quarantined; the handle
    /// keeps its claim on the main file.
    ///
    /// # Errors
    /// Returns `Admission` before any lower lock, `Unavailable` when the
    /// interlock or the transaction is busy, and `Quarantined` when the
    /// opened directory path no longer names the retained directory, a witness
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
        let outcome = OwnerStoreFileInterlockV1::try_acquire(
            &admitted,
            &native.witnesses.retained_directory_path(),
            &self.main_basename,
        )
        .map_err(|_| StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|interlock| require_namespace(interlock, native))
        .and_then(|_interlock| run_guarded(native, file_id, operation));
        conclude(admitted, outcome)
    }

    /// Close the native connection under admission and the interlock after
    /// a recheck of every retained witness, then release the native slot and
    /// the process-wide claim on the main file.
    ///
    /// # Errors
    /// Returns `Refused` with the untouched handle when shared admission
    /// refuses before any lower lock. A busy interlock, a changed witness or
    /// a failed close returns `Quarantined` and retains the connection until process exit
    /// (ADR-123 §6). A panic before the close completes retains it too.
    pub fn close(self) -> Result<(), OwnerStoreCloseErrorV1> {
        let context = Arc::clone(&self.context);
        let admitted = match context.admission().try_enter() {
            Ok(admitted) => admitted,
            Err(error) => {
                return Err(OwnerStoreCloseErrorV1::Refused {
                    error,
                    store: Box::new(self),
                })
            }
        };
        let Self {
            main_basename,
            native,
            ..
        } = self;
        let directory = native.witnesses.retained_directory_path();
        let key = native.witnesses.registry_key();
        let outcome = OwnerStoreFileInterlockV1::try_acquire(&admitted, &directory, &main_basename)
            .map_err(|_| StepV1::Retain)
            .and_then(|interlock| require_namespace(interlock, &native))
            .and_then(|_interlock| {
                close_native(native)
                    .then(|| {
                        context.release_native_slot();
                        release_identity(key);
                    })
                    .ok_or(StepV1::Retain)
            });
        conclude(admitted, outcome).map_err(|_| OwnerStoreCloseErrorV1::Quarantined)
    }
}

/// Keep a held interlock only while the canonical directory `SQLite`
/// remembered still names the retained directory. The interlock is taken
/// through the retained descriptor, but `SQLite` addresses `-wal` and `-shm`
/// by the remembered path, which a symlinked caller path can disagree with, so
/// after a swap its cleanup could delete another store's files: quarantine and
/// keep the claim instead (ADR-123 §6).
fn require_namespace<I>(interlock: I, native: &NativeOwnerV1) -> Result<I, StepV1> {
    native
        .witnesses
        .names_directory(&native.canonical_directory)
        .then_some(interlock)
        .ok_or(StepV1::Retain)
}

/// Dispose of the retained owner under the held interlock, which was taken
/// through the retained directory. The store stays inside `ManuallyDrop`
/// until `managed_close` owns the bare connection.
fn close_native(native: Retained<NativeOwnerV1>) -> bool {
    let NativeOwnerV1 {
        store,
        witnesses,
        native_witnesses,
        ..
    } = Retained::into_inner(native);
    dispose(store, witnesses, native_witnesses)
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

/// Take one interlock on the caller's path, screen and provision under it,
/// then prove the interlock's directory object and main file are the screened
/// ones: a path swapped between the two lookups would otherwise provision
/// companions in another directory, or bind a file other than the one the
/// lock is keyed on, under this lock. Both proofs refuse before any claim or
/// native open. The same interlock stays held through
/// the setup (ADR-123 §4).
fn bind(
    admitted: &OwnerStoreOperationV1<'_>,
    directory: &Path,
    main_basename: &str,
    pre_screen_key: SubjectStoreFileIdV1,
) -> Result<NativeOwnerV1, StepV1> {
    OwnerStoreFileInterlockV1::try_acquire(admitted, directory, main_basename)
        .ok()
        .and_then(|interlock| {
            #[cfg(test)]
            run_hook(&AFTER_INTERLOCK);
            let witnesses = OwnerStoreWitnessesV1::screen(directory, main_basename);
            #[cfg(test)]
            run_hook(&AFTER_SCREEN);
            witnesses
                .filter(|witnesses| {
                    witnesses.names_directory(&interlock.directory_path())
                        && witnesses.registry_key() == interlock.main_key()
                })
                .map(|witnesses| (interlock, witnesses))
        })
        .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|(_interlock, witnesses)| {
            setup(witnesses, directory, main_basename, pre_screen_key)
        })
}

/// Open and bind under the held interlock. The recheck proves the entries are
/// still the screened ones now that the lock is held. `is_claimed` and the
/// claim in `bind_native` are one atomic step only because that interlock is
/// held across both.
fn setup(
    witnesses: OwnerStoreWitnessesV1,
    directory: &Path,
    main_basename: &str,
    pre_screen_key: SubjectStoreFileIdV1,
) -> Result<NativeOwnerV1, StepV1> {
    Some(witnesses)
        .filter(OwnerStoreWitnessesV1::recheck)
        .filter(|witnesses| !is_claimed(witnesses.registry_key()))
        .and_then(|witnesses| {
            witnesses
                .sqlite_path(directory, main_basename)
                .and_then(|path| {
                    let mut canonical = path.clone();
                    canonical.pop();
                    open_native(&path).map(|store| (store, witnesses, canonical))
                })
        })
        .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|(store, witnesses, canonical)| {
            bind_native(store, witnesses, canonical, pre_screen_key)
        })
}

/// Open the screened main file: read-write, no create, no URI, no symlink,
/// the standard `unix` VFS and no reservation connection. The store leaves
/// here already inside `ManuallyDrop`, so no unwind can run its destructor.
fn open_native(path: &Path) -> Option<Retained<SqliteStore>> {
    #[cfg(test)]
    NATIVE_OPENS.with(|opens| opens.set(opens.get() + 1));
    Connection::open_with_flags_and_vfs(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        c"unix",
    )
    .ok()
    .map(|conn| {
        conn.set_prepared_statement_cache_capacity(super::SQLITE_STATEMENT_CACHE_CAPACITY);
        Retained::new(SqliteStore::with_connection(
            conn,
            None,
            Box::new(pos_crypto::chain::Blake3Hasher),
            0,
        ))
    })
}

/// Claim the main file's identity, then configure, prove and attach inside the
/// setup transaction; dispose of the connection and release the claim on a
/// proved refusal. A retained connection keeps the claim. The identity check
/// follows the proof at once.
fn bind_native(
    mut store: Retained<SqliteStore>,
    witnesses: OwnerStoreWitnessesV1,
    canonical_directory: PathBuf,
    pre_screen_key: SubjectStoreFileIdV1,
) -> Result<NativeOwnerV1, StepV1> {
    let file_id = witnesses.store_file_id();
    let key = witnesses.registry_key();
    // Atomic with the caller's `is_claimed` check only because the interlock
    // is held across both steps.
    claim_identity(key);
    let bound = configure(&store.conn)
        .then_some(())
        .ok_or(StepV1::Refuse(OwnerStoreBindingErrorV1::Unavailable))
        .and_then(|()| begin(&store.conn))
        .and_then(|()| prove_in_transaction(&store.conn, &witnesses))
        .and_then(|native_witnesses| {
            let attached = (file_id == pre_screen_key)
                .then_some(())
                .ok_or(OwnerStoreBindingErrorV1::Unavailable)
                .and_then(|()| {
                    validate_and_attach(&mut ProtectedStoreFileBindingV1 {
                        store: &mut store,
                        file_id,
                    })
                });
            finish(&store.conn, attached.is_ok())
                .and_then(|()| attached.map_err(StepV1::Refuse))
                .map(|()| native_witnesses)
        });
    match bound {
        Ok(native_witnesses) => Ok(NativeOwnerV1 {
            canonical_directory,
            store,
            witnesses,
            native_witnesses,
        }),
        Err(StepV1::Refuse(error)) => Err(if dispose(store, witnesses, ()) {
            release_identity(key);
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
    #[cfg(test)]
    assert!(!PANIC_SETUP.with(std::cell::Cell::get), "setup panic seam");
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
/// The store leaves `ManuallyDrop` only here, after the last step that could
/// unwind, so a panic never runs the connection's destructor.
fn dispose<R: 'static>(
    store: Retained<SqliteStore>,
    witnesses: OwnerStoreWitnessesV1,
    retained: R,
) -> bool {
    let safe = witnesses.recheck();
    #[cfg(test)]
    assert!(
        !PANIC_DISPOSE.with(std::cell::Cell::get),
        "dispose panic seam"
    );
    let SqliteStore { conn, .. } = Retained::into_inner(store);
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
#[cfg(not(test))]
const fn retain<T>(value: T) -> Retained<T> {
    Retained::new(value)
}

/// Test builds hand the value to the reclaim list instead of leaking it, so
/// the fixture closes the connection after its assertions.
#[cfg(test)]
fn retain<T: 'static>(value: T) -> Retained<T> {
    Retained::new(value)
}

/// Test-only stand-in for `ManuallyDrop` that parks dropped values.
///
/// Dropping it parks the value on a thread-local list, which the test fixture
/// reclaims once every assertion ran. Production keeps `ManuallyDrop` and
/// never runs the destructor.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod retained {
    use std::any::Any;
    use std::cell::RefCell;
    use std::ops::{Deref, DerefMut};

    thread_local! {
        static PARKED: RefCell<Vec<Box<dyn Any>>> = const { RefCell::new(Vec::new()) };
    }

    /// One value that is parked, not dropped, when this wrapper drops.
    pub(super) struct Retained<T: 'static>(Vec<T>);

    impl<T: 'static> Retained<T> {
        pub(super) fn new(value: T) -> Self {
            Self(vec![value])
        }

        pub(super) fn into_inner(mut this: Self) -> T {
            std::mem::take(&mut this.0).swap_remove(0)
        }
    }

    impl<T: 'static> Deref for Retained<T> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0[0]
        }
    }

    impl<T: 'static> DerefMut for Retained<T> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0[0]
        }
    }

    impl<T: 'static> Drop for Retained<T> {
        fn drop(&mut self) {
            for value in std::mem::take(&mut self.0) {
                PARKED
                    .try_with(|parked| parked.borrow_mut().push(Box::new(value)))
                    .unwrap_or(());
            }
        }
    }

    /// Really drop every parked value, closing its connection. Dropping one
    /// value can park another, so repeat until none remain.
    pub(super) fn reclaim() {
        loop {
            let batch = PARKED
                .try_with(|parked| std::mem::take(&mut *parked.borrow_mut()))
                .unwrap_or_default();
            if batch.is_empty() {
                break;
            }
            drop(batch);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::num::NonZeroU64;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::thread::LocalKey;

    use pos_core::{GatewayModeBindingHostV1, GatewayModeProfileRefV1};

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

    impl Drop for Fixture {
        /// Close every connection the test retained or quarantined, after
        /// all assertions ran, and forget its claim so a reused inode is
        /// not seen as claimed by a later test.
        fn drop(&mut self) {
            super::retained::reclaim();
            for key in [self.key, self.other_key] {
                if let SubjectStoreFileIdV1::Linux { device, inode } = key {
                    release_identity([device, inode]);
                }
            }
        }
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

        /// Open through a brand-new context for the same file.
        fn open_fresh_context(&self) -> Result<QualifiedSqliteStoreV1, OwnerStoreBindingErrorV1> {
            QualifiedSqliteStoreV1::open(
                Arc::new(OwnerStoreContextV1::default()),
                self.directory.path(),
                MAIN,
                self.key,
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
        Ok(GatewayModeProfileRefV1::try_new(
            "owner-store-binding-test",
            [7; 32],
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

    /// A complete bound store whose journal mode is `DELETE`, not WAL.
    fn installed_delete_journal() -> TestResult<Fixture> {
        let fixture = installed(true)?;
        Connection::open(fixture.path(""))?.query_row(
            "PRAGMA journal_mode = DELETE",
            [],
            |row| row.get::<_, String>(0),
        )?;
        Ok(fixture)
    }

    fn journal_mode(fixture: &Fixture) -> TestResult<String> {
        Ok(Connection::open(fixture.path(""))?
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
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

    fn closed(store: QualifiedSqliteStoreV1) -> TestResult {
        store.close().map_err(|error| format!("{error:?}").into())
    }

    /// Run `action` with `seam` set, catching an unwind it causes.
    fn with_panicking_seam<T>(
        seam: &'static LocalKey<Cell<bool>>,
        action: impl FnOnce() -> T,
    ) -> std::thread::Result<T> {
        with_seam(seam, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(action))
        })
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
        closed(store)?;
        let reopened = fixture.open()?;
        assert_eq!(reopened.store_file_id(), fixture.key);
        closed(reopened)?;
        assert!(!fixture.path("-wal").exists());
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
        let Some(refused) = store.close().err() else {
            return Err("an active admission must refuse the close".into());
        };
        assert_eq!(
            refused.to_string(),
            "owner store close refused by admission"
        );
        assert!(std::error::Error::source(&refused).is_none());
        let OwnerStoreCloseErrorV1::Refused { error, store } = refused else {
            return Err("an active admission must refuse the close".into());
        };
        assert_eq!(OwnerStoreBindingErrorV1::Admission(error), ACTIVE);
        active.complete_cleanly();
        // The refused close returned the untouched handle, so the slot stays
        // full until it is closed; a transient refusal does not leak it.
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        closed(*store)?;
        closed(fixture.open()?)?;
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
        closed(fixture.open()?)?;
        Ok(())
    }

    #[test]
    fn the_key_mismatch_is_checked_before_the_mode_binding() -> TestResult {
        let fixture = installed(false)?;
        assert_eq!(
            fixture.open_with(fixture.other_key).err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::ModeBinding(
                GatewayModeBindingErrorV1::Unbound
            ))
        );
        Ok(())
    }

    #[test]
    fn a_non_wal_main_file_is_refused_and_its_journal_mode_is_unchanged() -> TestResult {
        let fixture = installed_delete_journal()?;
        assert_eq!(journal_mode(&fixture)?, "delete");
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        assert_eq!(journal_mode(&fixture)?, "delete");
        assert_eq!(
            fixture.open().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn a_panic_during_setup_retains_the_open_connection() -> TestResult {
        let fixture = installed(true)?;
        assert!(with_panicking_seam(&PANIC_SETUP, || fixture.open()).is_err());
        // An unwinding setup must not run SQLite's destructor, which would
        // checkpoint and delete the WAL: the connection stays open.
        assert!(fixture.path("-wal").exists());
        assert!(!fixture.context.claim_native_slot());
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn a_panic_during_managed_close_retains_the_open_connection() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        assert!(with_panicking_seam(&PANIC_DISPOSE, || store.close()).is_err());
        assert!(fixture.path("-wal").exists());
        assert!(!fixture.context.claim_native_slot());
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn a_dropped_handle_keeps_its_file_unavailable_to_a_new_context() -> TestResult {
        let fixture = installed(true)?;
        drop(fixture.open()?);
        assert!(fixture.path("-wal").exists());
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
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
        closed(fixture.open()?)?;
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
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
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
        let quarantined = store.close().err();
        assert!(matches!(
            quarantined,
            Some(OwnerStoreCloseErrorV1::Quarantined)
        ));
        assert_eq!(
            quarantined.map(|error| error.to_string()),
            Some("protected owner store close quarantined".to_owned())
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
        // The quarantined handle is still alive: only the process-wide claim
        // can refuse a fresh context (the replaced WAL screens fine).
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        assert!(matches!(
            store.close().err(),
            Some(OwnerStoreCloseErrorV1::Refused {
                error: SubjectFieldOwnerReadErrorV1::ContextQuarantined,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn a_changed_witness_retains_the_connection_at_close() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        fixture.replace_wal()?;
        assert!(matches!(
            store.close().err(),
            Some(OwnerStoreCloseErrorV1::Quarantined)
        ));
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
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
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
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
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn a_live_store_refuses_a_fresh_context_and_stays_usable() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        // A second native connection would have failed this fresh proof.
        assert_eq!(store.guarded(|_| Ok::<(), ()>(()))?, Ok(()));
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        closed(store)?;
        closed(fixture.open_fresh_context()?)?;
        Ok(())
    }

    #[test]
    fn a_panic_in_a_guarded_operation_leaves_the_transaction_open_and_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.guarded(|_| -> Result<(), ()> { std::panic::resume_unwind(Box::new("closure")) })
        }));
        assert!(unwound.is_err());
        assert!(!store.native.store.conn.is_autocommit());
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(QUARANTINED));
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        drop(store);
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    /// Rename the fixture directory away and put a decoy directory with
    /// non-empty `-wal` and `-shm` at its path. Returns the moved path.
    fn swap_in_decoy(original: &Path) -> TestResult<PathBuf> {
        let mut moved = original.to_path_buf().into_os_string();
        moved.push("-moved");
        let moved = PathBuf::from(moved);
        std::fs::rename(original, &moved)?;
        std::fs::create_dir(original)?;
        std::fs::set_permissions(original, std::fs::Permissions::from_mode(0o700))?;
        for name in [format!("{MAIN}-wal"), format!("{MAIN}-shm")] {
            std::fs::write(original.join(name), b"decoy")?;
        }
        Ok(moved)
    }

    /// Assert the decoy files survived and the real store's files stayed in
    /// the renamed directory, then put the real directory back.
    fn assert_untouched_and_restore(original: &Path, moved: &Path) -> TestResult {
        for name in [format!("{MAIN}-wal"), format!("{MAIN}-shm")] {
            assert_eq!(std::fs::read(original.join(&name))?, b"decoy");
            assert!(moved.join(&name).exists());
        }
        assert!(moved.join(MAIN).exists());
        std::fs::remove_dir_all(original)?;
        std::fs::rename(moved, original)?;
        Ok(())
    }

    #[test]
    fn guarded_after_a_path_swap_quarantines_and_leaves_the_decoy_untouched() -> TestResult {
        let fixture = installed(true)?;
        let mut store = fixture.open()?;
        let original = fixture.directory.path().to_path_buf();
        let moved = swap_in_decoy(&original)?;
        let operated = store.guarded(|_| Ok::<(), ()>(()));
        assert_eq!(operated.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_eq!(store.guarded(|_| Ok::<(), ()>(())).err(), Some(QUARANTINED));
        assert_untouched_and_restore(&original, &moved)?;
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn close_after_a_path_swap_quarantines_and_leaves_the_decoy_untouched() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        let original = fixture.directory.path().to_path_buf();
        let moved = swap_in_decoy(&original)?;
        let closed_after_swap = store.close();
        assert!(matches!(
            closed_after_swap.err(),
            Some(OwnerStoreCloseErrorV1::Quarantined)
        ));
        assert_untouched_and_restore(&original, &moved)?;
        assert_eq!(
            fixture.open_fresh_context().err(),
            Some(OwnerStoreBindingErrorV1::Unavailable)
        );
        Ok(())
    }

    /// Install a hook that swaps in a decoy directory and records the moved path.
    fn swap_at(
        slot: &'static std::thread::LocalKey<HookSlot>,
        original: &Path,
        decoy: fn(&Path) -> TestResult<PathBuf>,
    ) -> Rc<RefCell<Option<PathBuf>>> {
        let swapped = Rc::new(RefCell::new(None));
        let hook_swapped = Rc::clone(&swapped);
        let hook_original = original.to_path_buf();
        slot.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                *hook_swapped.borrow_mut() = decoy(&hook_original).ok();
            }));
        });
        swapped
    }

    /// Like `swap_in_decoy`, but the decoy also holds a private main file and
    /// private companions, so it passes the screening.
    fn swap_in_screenable_decoy(original: &Path) -> TestResult<PathBuf> {
        let moved = swap_in_decoy(original)?;
        for name in [
            MAIN.to_owned(),
            format!("{MAIN}-wal"),
            format!("{MAIN}-shm"),
        ] {
            std::fs::remove_file(original.join(&name)).ok();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(original.join(&name))?;
        }
        Ok(moved)
    }

    fn restore(original: &Path, moved: &Path) -> TestResult {
        std::fs::remove_dir_all(original)?;
        std::fs::rename(moved, original)?;
        Ok(())
    }

    /// The identity proof still passes here (both descriptors name the real
    /// directory); the refusal comes from the canonical path check before the
    /// native open.
    #[test]
    fn a_path_swap_between_screening_and_the_native_open_is_refused_without_a_claim() -> TestResult
    {
        let fixture = installed(true)?;
        let original = fixture.directory.path().to_path_buf();
        let swapped = swap_at(&AFTER_SCREEN, &original, swap_in_decoy);
        let refused = fixture.open();
        let moved = swapped.borrow_mut().take().ok_or("hook did not run")?;
        restore(&original, &moved)?;
        assert_eq!(refused.err(), Some(OwnerStoreBindingErrorV1::Unavailable));
        closed(fixture.open()?)?;
        Ok(())
    }

    /// The swapped directory is screenable, so only the identity proof refuses it.
    #[test]
    fn a_path_swap_between_the_interlock_and_the_screening_is_refused_without_a_claim() -> TestResult
    {
        let fixture = installed(true)?;
        let original = fixture.directory.path().to_path_buf();
        let swapped = swap_at(&AFTER_INTERLOCK, &original, swap_in_screenable_decoy);
        let refused = fixture.open();
        let moved = swapped.borrow_mut().take().ok_or("hook did not run")?;
        restore(&original, &moved)?;
        assert_eq!(refused.err(), Some(OwnerStoreBindingErrorV1::Unavailable));
        closed(fixture.open()?)?;
        Ok(())
    }

    fn entry_names(directory: &Path) -> TestResult<Vec<String>> {
        let mut names = std::fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    /// The replacement main file is private, empty and singly linked, so the
    /// screening accepts it and, as ADR-123 section 4 orders it, provisions the
    /// missing empty `-wal` and `-shm` before the identity proof refuses: the
    /// interlock is keyed on the original inode, the replacement has another.
    /// Nothing removes those two companions; no claim and no native open
    /// happen, and a later clean open tolerates them.
    #[test]
    fn a_main_file_replaced_in_place_after_the_interlock_is_refused_before_any_claim() -> TestResult
    {
        let fixture = installed(true)?;
        let original = fixture.directory.path().to_path_buf();
        let before = entry_names(&original)?;
        let opens_before = NATIVE_OPENS.with(Cell::get);
        let kept = original.join(format!("{MAIN}.kept"));
        let hook_kept = kept.clone();
        let hook_main = original.join(MAIN);
        AFTER_INTERLOCK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&hook_main, &hook_kept).ok();
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&hook_main)
                    .ok();
            }));
        });
        let refused = fixture.open();
        assert_eq!(refused.err(), Some(OwnerStoreBindingErrorV1::Unavailable));
        assert!(kept.exists());
        let replacement = std::fs::metadata(original.join(MAIN))?;
        assert!(!is_claimed([replacement.dev(), replacement.ino()]));
        assert_eq!(NATIVE_OPENS.with(Cell::get), opens_before);
        std::fs::remove_file(original.join(MAIN))?;
        std::fs::rename(&kept, original.join(MAIN))?;
        let mut provisioned = before;
        provisioned.extend([format!("{MAIN}-shm"), format!("{MAIN}-wal")]);
        provisioned.sort();
        assert_eq!(entry_names(&original)?, provisioned);
        for suffix in ["-shm", "-wal"] {
            let companion = std::fs::metadata(original.join(format!("{MAIN}{suffix}")))?;
            assert_eq!(companion.len(), 0);
            assert_eq!(companion.permissions().mode() & 0o777, 0o600);
        }
        closed(fixture.open()?)?;
        assert_eq!(NATIVE_OPENS.with(Cell::get), opens_before + 1);
        Ok(())
    }

    #[test]
    fn a_retargeted_symlink_cannot_hide_a_swapped_canonical_directory() -> TestResult {
        let fixture = installed(true)?;
        let real = fixture.directory.path().to_path_buf();
        let holder = tempfile::tempdir()?;
        let link = holder.path().join("link");
        std::os::unix::fs::symlink(&real, &link)?;
        let mut store =
            QualifiedSqliteStoreV1::open(Arc::clone(&fixture.context), &link, MAIN, fixture.key)?;
        let moved = swap_in_decoy(&real)?;
        std::fs::remove_file(&link)?;
        std::os::unix::fs::symlink(&moved, &link)?;
        let operated = store.guarded(|_| Ok::<(), ()>(()));
        assert_eq!(operated.err(), Some(OwnerStoreBindingErrorV1::Quarantined));
        assert_untouched_and_restore(&real, &moved)?;
        Ok(())
    }

    #[test]
    fn a_failed_managed_close_retains_and_quarantines() -> TestResult {
        let fixture = installed(true)?;
        let store = fixture.open()?;
        let result = with_seam(&FAIL_MANAGED_CLOSE, || store.close());
        assert!(matches!(
            result.err(),
            Some(OwnerStoreCloseErrorV1::Quarantined)
        ));
        assert_eq!(fixture.open().err(), Some(QUARANTINED));
        Ok(())
    }
}
