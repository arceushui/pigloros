//! The `SQLite` registry durability protocol shared by the Plugin trust and fallback registries.
//!
//! Both adapters (ADR-103 and ADR-119) run one write the same way: the poison check
//! (`StorePoisoned`); the autocommit check (`NestedTransaction`); the WAL check (`WalRequired`);
//! a read of the connection's current `synchronous` level; `PRAGMA synchronous=FULL` with a
//! read-back; `BEGIN IMMEDIATE`; the work; `COMMIT` or `ROLLBACK`; and the restore of the recorded
//! level with a read-back. From the moment `FULL` is set, every exit path restores the recorded
//! level. After a failed `COMMIT` the protocol issues `ROLLBACK` (its error is ignored when the
//! connection is already in autocommit) and requires autocommit before it touches the level,
//! because `SQLite` refuses to change the safety level inside a transaction. A connection still
//! inside a transaction then, or a restore that fails, poisons the handle: the write returns
//! `StorageIndeterminate` and every later registry call returns `StorePoisoned` until the store
//! is dropped and reopened.
//!
//! The module is adapter-neutral and builds on every target: each registry passes in its own
//! poison cell through [`DurableRegistryV1`] and maps the protocol's failures to its own error
//! through [`DurabilityErrorV1`]. The registry-specific parts (the erasure fence, the trust
//! registry's read transaction) stay in the adapters; that read transaction still uses the shared
//! `committed`, `rollback_to_autocommit` and `poison` steps.

use std::cell::Cell;

use rusqlite::Connection;

fn query_journal(connection: &Connection) -> rusqlite::Result<String> {
    connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))
}

fn query_level(connection: &Connection) -> rusqlite::Result<i64> {
    connection.query_row("PRAGMA synchronous", [], |row| row.get(0))
}

fn exec_set_full(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA synchronous=FULL")
}

fn exec_restore(connection: &Connection, level: i64) -> rusqlite::Result<()> {
    connection.execute_batch(&format!("PRAGMA synchronous={level}"))
}

fn exec_commit(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("COMMIT")
}

fn exec_rollback(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("ROLLBACK")
}

use seam::{
    commit, entry_level, full_read_back, journal_mode, restore_read_back, restore_statement,
    rollback, set_full_statement,
};

/// The value `PRAGMA synchronous` reads back for `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

/// The errors one registry reports for the steps of the durability protocol.
pub(super) trait DurabilityErrorV1: Sized {
    /// A handle whose connection state became unknown earlier.
    const STORE_POISONED: Self;
    /// The connection is already inside a transaction.
    const NESTED_TRANSACTION: Self;
    /// The database is not in WAL mode.
    const WAL_REQUIRED: Self;
    /// The outcome of a durability step is unknown.
    const STORAGE_INDETERMINATE: Self;

    /// Map a failed `SQLite` statement to the registry's storage error.
    fn storage(error: &rusqlite::Error) -> Self;
}

fn require_wal<E: DurabilityErrorV1>(connection: &Connection) -> Result<(), E> {
    let mode = journal_mode(connection).map_err(|error| E::storage(&error))?;
    if mode == "wal" {
        Ok(())
    } else {
        Err(E::WAL_REQUIRED)
    }
}

/// Set `synchronous=FULL` and read it back; either failure leaves the outcome unknown.
fn set_full<E: DurabilityErrorV1>(connection: &Connection) -> Result<(), E> {
    let full = set_full_statement(connection)
        .and_then(|()| full_read_back(connection))
        .is_ok_and(|level| level == SYNCHRONOUS_FULL);
    if full {
        Ok(())
    } else {
        Err(E::STORAGE_INDETERMINATE)
    }
}

/// Whether `level` is the connection's level again, in autocommit, as read back.
fn restore(connection: &Connection, level: i64) -> bool {
    connection.is_autocommit()
        && restore_statement(connection, level)
            .and_then(|()| restore_read_back(connection))
            .is_ok_and(|read| read == level)
}

fn begin<E: DurabilityErrorV1>(connection: &Connection) -> Result<(), E> {
    connection
        .execute_batch(super::begin_immediate_sql())
        .map_err(|error| E::storage(&error))
}

/// Run `COMMIT` through the seam and report whether it succeeded.
pub(super) fn committed(connection: &Connection) -> bool {
    commit(connection).is_ok()
}

/// Roll back whatever is open and report whether the connection is in autocommit afterwards.
///
/// Without an open transaction the reported error carries no information: `SQLite` may already
/// have rolled the transaction back.
pub(super) fn rollback_to_autocommit(connection: &Connection) -> bool {
    drop(rollback(connection));
    connection.is_autocommit()
}

/// One registry's view of the store's connection and of that registry's own poison cell.
pub(super) struct DurableRegistryV1<'a> {
    pub(super) connection: &'a Connection,
    pub(super) poisoned: &'a Cell<bool>,
}

impl DurableRegistryV1<'_> {
    /// A poisoned handle fails every registry call.
    pub(super) const fn ensure_usable<E: DurabilityErrorV1>(&self) -> Result<(), E> {
        if self.poisoned.get() {
            Err(E::STORE_POISONED)
        } else {
            Ok(())
        }
    }

    /// Record that the connection's state is unknown until the store is reopened.
    pub(super) fn poison(&self) {
        self.poisoned.set(true);
    }

    /// Restore the recorded `synchronous` level, or poison the handle.
    fn restore_level<E: DurabilityErrorV1>(&self, level: i64) -> Result<(), E> {
        if restore(self.connection, level) {
            Ok(())
        } else {
            self.poison();
            Err(E::STORAGE_INDETERMINATE)
        }
    }

    /// Everything up to and including `BEGIN IMMEDIATE`; returns the level to restore.
    fn enter_full_durability<E: DurabilityErrorV1>(&self) -> Result<i64, E> {
        let connection = self.connection;
        if !connection.is_autocommit() {
            return Err(E::NESTED_TRANSACTION);
        }
        require_wal::<E>(connection)?;
        let entry = entry_level(connection).map_err(|error| E::storage(&error))?;
        set_full::<E>(connection)
            .and_then(|()| begin(connection))
            .or_else(|error| self.restore_level(entry).and(Err(error)))
            .map(|()| entry)
    }

    /// Roll back, then restore the recorded level.
    ///
    /// A connection that is still inside a transaction after `ROLLBACK` cannot change its level:
    /// the handle is poisoned instead.
    fn abandon_and_restore<E: DurabilityErrorV1>(&self, level: i64) -> Result<(), E> {
        if rollback_to_autocommit(self.connection) {
            self.restore_level(level)
        } else {
            self.poison();
            Err(E::STORAGE_INDETERMINATE)
        }
    }

    /// `COMMIT`, then restore the recorded level. A failed `COMMIT` is an unknown outcome.
    fn commit_and_restore<E: DurabilityErrorV1>(&self, level: i64) -> Result<(), E> {
        if committed(self.connection) {
            self.restore_level(level)
        } else {
            self.abandon_and_restore(level)
                .and(Err(E::STORAGE_INDETERMINATE))
        }
    }

    /// Run `work` in one `BEGIN IMMEDIATE` transaction at `synchronous=FULL`.
    pub(super) fn transaction<E: DurabilityErrorV1, T>(
        &self,
        work: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.ensure_usable::<E>()?;
        let level = self.enter_full_durability::<E>()?;
        match work() {
            Ok(value) => self.commit_and_restore(level).map(|()| value),
            Err(error) => self.abandon_and_restore(level).and(Err(error)),
        }
    }
}

/// The durability statements the protocol runs. A production build runs the real statements; a
/// test build substitutes each whole function so a test can make exactly that step fail (the
/// same seam style as `recipient_owner`). The real statements above are compiled in both.
#[cfg(not(test))]
mod seam {
    pub(super) use super::{
        exec_commit as commit, exec_restore as restore_statement, exec_rollback as rollback,
        exec_set_full as set_full_statement, query_journal as journal_mode,
        query_level as entry_level, query_level as full_read_back,
        query_level as restore_read_back,
    };
}

/// The test seam; both registries' tests drive it through their adapter's `seam` name.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod seam {
    use std::cell::{Cell, RefCell};

    use rusqlite::Connection;

    use super::{
        exec_commit, exec_restore, exec_rollback, exec_set_full, query_journal, query_level,
    };

    /// One step of the durability protocol that a test can make fail.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in crate::sqlite) enum Step {
        ReadJournal,
        ReadEntry,
        SetFull,
        ReadBackFull,
        Restore,
        ReadBackRestore,
        /// A `COMMIT` that succeeds but reports failure: a lost acknowledgement.
        LostAcknowledgement,
        /// A `ROLLBACK` that never runs, leaving the transaction open.
        Rollback,
    }

    thread_local! {
        /// The one step that fails on this thread.
        pub(in crate::sqlite) static FAULT: Cell<Option<Step>> = const { Cell::new(None) };
        /// The `synchronous` level read just before the last `COMMIT`.
        pub(in crate::sqlite) static LEVEL_AT_COMMIT: Cell<Option<i64>> =
            const { Cell::new(None) };
        /// Runs just before the restore statement, while the erasure fence is still held.
        pub(in crate::sqlite) static RESTORE_PROBE: RefCell<Option<Box<dyn Fn()>>> =
            const { RefCell::new(None) };
    }

    fn injected(step: Step) -> bool {
        FAULT.with(Cell::get) == Some(step)
    }

    fn fail_if(step: Step) -> rusqlite::Result<()> {
        if injected(step) {
            Err(rusqlite::Error::InvalidQuery)
        } else {
            Ok(())
        }
    }

    pub(super) fn journal_mode(connection: &Connection) -> rusqlite::Result<String> {
        fail_if(Step::ReadJournal).and_then(|()| query_journal(connection))
    }

    pub(super) fn entry_level(connection: &Connection) -> rusqlite::Result<i64> {
        fail_if(Step::ReadEntry).and_then(|()| query_level(connection))
    }

    pub(super) fn set_full_statement(connection: &Connection) -> rusqlite::Result<()> {
        fail_if(Step::SetFull).and_then(|()| exec_set_full(connection))
    }

    /// A failed read-back reads a value that is never a level.
    pub(super) fn full_read_back(connection: &Connection) -> rusqlite::Result<i64> {
        if injected(Step::ReadBackFull) {
            Ok(-1)
        } else {
            query_level(connection)
        }
    }

    pub(super) fn restore_statement(connection: &Connection, level: i64) -> rusqlite::Result<()> {
        RESTORE_PROBE.with(|probe| {
            if let Some(probe) = probe.borrow().as_ref() {
                probe();
            }
        });
        fail_if(Step::Restore).and_then(|()| exec_restore(connection, level))
    }

    pub(super) fn restore_read_back(connection: &Connection) -> rusqlite::Result<i64> {
        fail_if(Step::ReadBackRestore).and_then(|()| query_level(connection))
    }

    pub(super) fn commit(connection: &Connection) -> rusqlite::Result<()> {
        LEVEL_AT_COMMIT.with(|level| level.set(query_level(connection).ok()));
        if injected(Step::LostAcknowledgement) {
            exec_commit(connection).and(Err(rusqlite::Error::InvalidQuery))
        } else {
            exec_commit(connection)
        }
    }

    pub(super) fn rollback(connection: &Connection) -> rusqlite::Result<()> {
        if injected(Step::Rollback) {
            Ok(())
        } else {
            exec_rollback(connection)
        }
    }
}
