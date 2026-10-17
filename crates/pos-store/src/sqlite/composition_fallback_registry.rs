//! `SQLite` adapter for the ADR-119 composition fallback registry port.
//!
//! The adapter is `impl CompositionFallbackRegistryV1 for SqliteStore`, so the registry rows and
//! the declaration or activation Event share the store's one connection and one WAL database
//! transaction. The decisions are the shared `plan_*` functions of
//! `crate::composition_fallback_registry::logic`; this file reads and writes the plan and orders
//! the locks.
//!
//! # Lock order and durability
//!
//! The reads run the poison check and the schema check, then one statement, with no
//! transaction. A write runs, in this order: the poison check (`StorePoisoned`); for `declare`
//! and `activate` the erasure fence of the target Timeline (`EventRejected`), which encloses
//! everything below up to and including the durability restore; the autocommit check
//! (`NestedTransaction`); the WAL check (`WalRequired`); a read of the connection's current
//! `synchronous` level; `PRAGMA synchronous=FULL` with a read-back; `BEGIN IMMEDIATE`; the work;
//! `COMMIT` or `ROLLBACK`; and the restore of the recorded level with a read-back. This is the
//! Plugin trust registry's protocol: from the moment `FULL` is set, every exit path restores the
//! recorded level; after a failed `COMMIT` the adapter rolls back and requires autocommit before
//! it touches the level; a connection still inside a transaction then, or a restore that fails,
//! poisons the handle, and every later registry call returns `StorePoisoned` until the store is
//! dropped and reopened.
//!
//! The Event is appended inside the open transaction through the same guard chain as
//! `EventStore::append` (`guarded_generic_append`), whose savepoint nests inside it. The fold
//! reads the target Timeline on the same connection inside the transaction.

use pos_core::store::SeqRange;
use pos_core::{ErasureProtectedOperationV1, Event, EventDraft, Hash, Seq, TimelineId};
use rusqlite::Connection;

use super::composition_fallback_registry_rows::{self as rows, storage_error};
use super::composition_fallback_registry_schema as schema;
use super::SqliteStore;
use crate::composition_fallback_registry::logic::{
    event_identity, payload_digest, plan_activate, plan_declare, require, FallbackPlanV1,
    FallbackReadsV1, FallbackResult,
};
use crate::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as Error, CompositionFallbackRegistryV1,
    FallbackActivateRequestV1, FallbackCommitOutcomeV1, FallbackCommitReceiptV1,
    FallbackDeclareRequestV1, FallbackEventIdentityV1, FallbackLedgerRowV1,
    FallbackProvisionOutcomeV1, FallbackRegistryRowV1,
};

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

/// The durability statements the protocol runs. A production build runs the real statements; a
/// test build substitutes each whole function so a test can make exactly that step fail.
#[cfg(not(test))]
mod seam {
    pub(super) use super::{
        exec_commit as commit, exec_restore as restore_statement, exec_rollback as rollback,
        exec_set_full as set_full_statement, query_journal as journal_mode,
        query_level as entry_level, query_level as full_read_back,
        query_level as restore_read_back,
    };
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod seam {
    use std::cell::Cell;

    use rusqlite::Connection;

    use super::{
        exec_commit, exec_restore, exec_rollback, exec_set_full, query_journal, query_level,
    };

    /// One step of the durability protocol that a test can make fail.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum Step {
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
        pub(super) static FAULT: Cell<Option<Step>> = const { Cell::new(None) };
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
        fail_if(Step::Restore).and_then(|()| exec_restore(connection, level))
    }

    pub(super) fn restore_read_back(connection: &Connection) -> rusqlite::Result<i64> {
        fail_if(Step::ReadBackRestore).and_then(|()| query_level(connection))
    }

    pub(super) fn commit(connection: &Connection) -> rusqlite::Result<()> {
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

use seam::{
    commit, entry_level, full_read_back, journal_mode, restore_read_back, restore_statement,
    rollback, set_full_statement,
};

/// The value `PRAGMA synchronous` reads back for `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

fn require_wal(connection: &Connection) -> FallbackResult<()> {
    journal_mode(connection)
        .map_err(|error| storage_error(&error))
        .and_then(|mode| require(mode == "wal", Error::WalRequired))
}

/// Set `synchronous=FULL` and read it back; either failure leaves the outcome unknown.
fn set_full(connection: &Connection) -> FallbackResult<()> {
    let full = set_full_statement(connection)
        .and_then(|()| full_read_back(connection))
        .is_ok_and(|level| level == SYNCHRONOUS_FULL);
    require(full, Error::StorageIndeterminate)
}

/// Whether `level` is the connection's level again, in autocommit, as read back.
fn restore(connection: &Connection, level: i64) -> bool {
    connection.is_autocommit()
        && restore_statement(connection, level)
            .and_then(|()| restore_read_back(connection))
            .is_ok_and(|read| read == level)
}

fn begin(connection: &Connection) -> FallbackResult<()> {
    connection
        .execute_batch(super::begin_immediate_sql())
        .map_err(|error| storage_error(&error))
}

/// Roll back whatever is open and report whether the connection is in autocommit afterwards.
fn rollback_to_autocommit(connection: &Connection) -> bool {
    drop(rollback(connection));
    connection.is_autocommit()
}

/// The logic's view of the open transaction; private, so no caller reads Events through it.
struct SqliteFallbackViewV1<'a> {
    connection: &'a Connection,
}

impl FallbackReadsV1 for SqliteFallbackViewV1<'_> {
    fn stored_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>> {
        rows::load_row(self.connection, scope, timeline)
    }

    fn stored_policy(&self, policy_digest: Hash) -> FallbackResult<Option<Vec<u8>>> {
        rows::load_policy(self.connection, policy_digest)
    }

    fn stored_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
        rows::load_ledger(self.connection, scope, timeline)
    }

    fn timeline_events(&self, timeline: TimelineId) -> FallbackResult<Vec<Event>> {
        SqliteStore::read_unchecked_on(self.connection, timeline, SeqRange::all())
            .or(Err(Error::TimelineUnavailable))
    }

    fn timeline_head(&self, timeline: TimelineId) -> FallbackResult<Seq> {
        SqliteStore::logical_head_unchecked_on(self.connection, timeline)
            .or(Err(Error::TimelineUnavailable))
    }
}

impl SqliteStore {
    /// A poisoned handle fails every registry call.
    const fn ensure_fallback_usable(&self) -> FallbackResult<()> {
        let poisoned = self.composition_fallback_poisoned.get();
        require(!poisoned, Error::StorePoisoned)
    }

    /// Record a failed restore: the connection's state is unknown until the store is reopened.
    fn poison_fallback(&self) -> Error {
        self.composition_fallback_poisoned.set(true);
        Error::StorageIndeterminate
    }

    /// Restore the recorded `synchronous` level, or poison the handle.
    fn restore_fallback_level(&self, level: i64) -> FallbackResult<()> {
        require(restore(&self.conn, level), Error::StorageIndeterminate)
            .map_err(|_| self.poison_fallback())
    }

    /// Everything up to and including `BEGIN IMMEDIATE`; returns the level to restore.
    fn enter_fallback_durability(&self) -> FallbackResult<i64> {
        let connection = &self.conn;
        require(connection.is_autocommit(), Error::NestedTransaction)?;
        require_wal(connection)?;
        let entry = entry_level(connection).map_err(|error| storage_error(&error))?;
        set_full(connection)
            .and_then(|()| begin(connection))
            .or_else(|error| self.restore_fallback_level(entry).and(Err(error)))
            .map(|()| entry)
    }

    /// Roll back, then restore the recorded level; a connection still in a transaction poisons.
    fn abandon_fallback(&self, level: i64) -> FallbackResult<()> {
        let rolled_back = rollback_to_autocommit(&self.conn);
        require(rolled_back, Error::StorageIndeterminate)
            .map_err(|_| self.poison_fallback())
            .and_then(|()| self.restore_fallback_level(level))
    }

    /// `COMMIT`, then restore the recorded level. A failed `COMMIT` is an unknown outcome.
    fn commit_fallback(&self, level: i64) -> FallbackResult<()> {
        match commit(&self.conn) {
            Ok(()) => self.restore_fallback_level(level),
            Err(_) => self
                .abandon_fallback(level)
                .and(Err(Error::StorageIndeterminate)),
        }
    }

    /// Run `work` in one `BEGIN IMMEDIATE` transaction at `synchronous=FULL`.
    fn fallback_transaction<T>(
        &self,
        work: &impl Fn(&Self) -> FallbackResult<T>,
    ) -> FallbackResult<T> {
        self.ensure_fallback_usable()?;
        let level = self.enter_fallback_durability()?;
        match work(self) {
            Ok(value) => self.commit_fallback(level).map(|()| value),
            Err(error) => self.abandon_fallback(level).and(Err(error)),
        }
    }

    /// Run `work` as a transaction inside the erasure fence of the target Timeline.
    ///
    /// A missing gate or a refused fence is `EventRejected`.
    fn fallback_event_transaction<T>(
        &mut self,
        timeline: TimelineId,
        work: &impl Fn(&Self) -> FallbackResult<T>,
    ) -> FallbackResult<T> {
        self.ensure_fallback_usable()?;
        let append = ErasureProtectedOperationV1::Append;
        let fenced = self.with_erasure_fence(timeline, append, |store| {
            Ok(store.fallback_transaction(work))
        });
        fenced
            .or(Err(Error::EventRejected))
            .and_then(std::convert::identity)
    }

    /// Append the declaration or activation Event under the guards of `EventStore::append`.
    ///
    /// The store's own payload hash must equal `BLAKE3-256(payload)`, so a store with another
    /// hasher never commits.
    fn append_fallback_event(
        &self,
        timeline: TimelineId,
        draft: &EventDraft,
    ) -> FallbackResult<FallbackEventIdentityV1> {
        let digest = payload_digest(self.hasher.as_ref(), draft)?;
        let appended = self.guarded_generic_append(timeline, std::slice::from_ref(draft));
        event_identity(appended, digest)
    }

    /// Write the plan: return a replay, or append the Event and then write the rows.
    fn write_fallback_plan(
        &self,
        scope: &str,
        timeline: TimelineId,
        plan: FallbackPlanV1,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        match plan {
            FallbackPlanV1::Replay(row) => Ok(FallbackCommitReceiptV1 {
                row,
                outcome: FallbackCommitOutcomeV1::IdempotentReplay,
            }),
            FallbackPlanV1::Commit(commit) => {
                let event = self.append_fallback_event(timeline, &commit.draft)?;
                let row = commit.ledger_row(event);
                let connection = &self.conn;
                let retained = commit.policy.as_ref();
                rows::write_row(connection, scope, timeline, &commit.row)
                    .and_then(|()| {
                        retained.map_or(Ok(()), |(digest, bytes)| {
                            rows::insert_policy(connection, *digest, bytes)
                        })
                    })
                    .and_then(|()| rows::insert_ledger(connection, scope, timeline, &row))
                    .map(|()| FallbackCommitReceiptV1 {
                        row,
                        outcome: FallbackCommitOutcomeV1::Committed,
                    })
            }
        }
    }

    /// Plan and write one operation in the target Timeline's fenced transaction.
    fn fallback_operation(
        &mut self,
        scope: &str,
        timeline: TimelineId,
        plan: impl Fn(&dyn FallbackReadsV1) -> FallbackResult<FallbackPlanV1>,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        self.fallback_event_transaction(timeline, &|store: &Self| {
            let connection = &store.conn;
            schema::require_present(connection)
                .and_then(|()| plan(&SqliteFallbackViewV1 { connection }))
                .and_then(|planned| store.write_fallback_plan(scope, timeline, planned))
        })
    }

    /// Run a read on the validated schema; a poisoned handle fails first.
    fn fallback_read<T>(
        &self,
        read: impl FnOnce(&Connection) -> FallbackResult<T>,
    ) -> FallbackResult<T> {
        self.ensure_fallback_usable()?;
        schema::require_present(&self.conn).and_then(|()| read(&self.conn))
    }
}

const fn provision_outcome(created: bool) -> FallbackProvisionOutcomeV1 {
    if created {
        FallbackProvisionOutcomeV1::Created
    } else {
        FallbackProvisionOutcomeV1::Unchanged
    }
}

impl CompositionFallbackRegistryV1 for SqliteStore {
    fn provision_fallback_registry(&mut self) -> FallbackResult<FallbackProvisionOutcomeV1> {
        self.fallback_transaction(&|store: &Self| {
            schema::ensure_for_provision(&store.conn).map(provision_outcome)
        })
    }

    fn declare(
        &mut self,
        request: &FallbackDeclareRequestV1,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        let timeline = request.target.timeline;
        self.fallback_operation(&request.scope, timeline, |reads| {
            plan_declare(reads, request)
        })
    }

    fn activate(
        &mut self,
        request: &FallbackActivateRequestV1,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        let timeline = request.target.timeline;
        self.fallback_operation(&request.scope, timeline, |reads| {
            plan_activate(reads, request)
        })
    }

    fn registry_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>> {
        self.fallback_read(|connection| rows::load_row(connection, scope, timeline))
    }

    fn lookup_declaration(
        &self,
        scope: &str,
        timeline: TimelineId,
        policy_digest: Hash,
    ) -> FallbackResult<Option<FallbackLedgerRowV1>> {
        self.fallback_ledger(scope, timeline)
            .map(|ledger| ledger.into_iter().find(|row| row.declares(policy_digest)))
    }

    fn lookup_activation(
        &self,
        scope: &str,
        timeline: TimelineId,
        entry_key: &str,
        closing_tenure_ordinal: u64,
    ) -> FallbackResult<Option<FallbackLedgerRowV1>> {
        self.fallback_ledger(scope, timeline).map(|ledger| {
            ledger
                .into_iter()
                .find(|row| row.closes(entry_key, closing_tenure_ordinal))
        })
    }

    fn retained_policy(&self, policy_digest: Hash) -> FallbackResult<Option<Vec<u8>>> {
        self.fallback_read(|connection| rows::load_policy(connection, policy_digest))
    }

    fn fallback_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
        self.fallback_read(|connection| rows::load_ledger(connection, scope, timeline))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "composition_fallback_registry_tests.rs"]
mod tests;
