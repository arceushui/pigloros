//! `SQLite` adapter for the ADR-103 revision 4 Plugin trust policy registry port.
//!
//! The adapter is `impl PluginTrustPolicyRegistryV1 for SqliteStore`, so the registry rows and
//! the activation Event share the store's one connection and one WAL database transaction. The
//! decisions themselves are the shared `plan_*` functions of
//! `crate::plugin_trust_registry::logic`; this file only reads and writes the plan through
//! [`SqliteTransactionV1`] and orders the locks.
//!
//! # Lock order and durability (decisions 3 and 7)
//!
//! A mutating operation runs, in this order: the poison check (`StorePoisoned`); for `admit` and
//! `rollback` the erasure fence of the activation Timeline (`ActivationEventRejected`), which
//! encloses everything below up to and including the durability restore; the autocommit check
//! (`NestedTransaction`); the WAL check (`WalRequired`); a read of the connection's current
//! `synchronous` level; `PRAGMA synchronous=FULL` with a read-back; `BEGIN IMMEDIATE`; the work;
//! `COMMIT` or `ROLLBACK`; and the restore of the recorded level with a read-back. From the
//! moment `FULL` is set, every exit path restores the recorded level, so the connection never
//! leaves at a different level than it entered with. After a failed `COMMIT` the adapter issues
//! `ROLLBACK` (its error is ignored when the connection is already in autocommit) and requires
//! autocommit before it touches the level, because `SQLite` refuses to change the safety level
//! inside a transaction. A connection that is still inside a transaction then, or a restore that
//! fails, poisons the handle: the operation returns `StorageIndeterminate` and every later
//! registry call, reads included, returns `StorePoisoned` until the store is dropped and reopened.
//!
//! The activation Event is appended inside the open transaction through the same guard chain as
//! `EventStore::append` (`guarded_generic_append`); `append_visible` opens a savepoint inside the
//! open transaction, which is expected.

use pos_conformance::{PluginFloorStateV1, PluginTrustPolicyAnchorV1};
use pos_core::{ErasureProtectedOperationV1, TimelineId};
use pos_crypto::plugin_trust::{
    ValidatedPluginManifestProjectionV1, VerifiedPluginTrustEvidenceV1,
};
use rusqlite::Connection;

use super::plugin_trust_registry_rows::{self as rows, storage_error, RegistryResult};
use super::plugin_trust_registry_schema as schema;
use super::SqliteStore;
use crate::plugin_trust_registry::logic::{
    plan_admit, plan_advance, plan_provision, plan_rollback, AdmitPlanV1, AdvancePlanV1,
    PluginTrustTransactionV1, PolicyInputV1, RetainedScopeV1, RollbackPlanV1,
};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActivationEventInputV1, ActiveReleaseV1,
    AdmittedPluginReleaseReceiptV1, PluginRollbackReceiptV1, PluginTrustCommitOutcomeV1,
    PluginTrustLedgerRowV1, PluginTrustPolicyRegistryErrorV1, PluginTrustPolicyRegistryV1,
    PolicyAdvanceOutcomeV1, ProvisionOutcomeV1, RetainedPolicyStateV1, RetainedReleaseDecisionV1,
    TrustedUtcSecondV1,
};

/// The value `PRAGMA synchronous` reads back for `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

/// One statement of the durability protocol, so a unit test can make exactly that step fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    /// `PRAGMA journal_mode`.
    ReadJournal,
    /// The read of the entry `synchronous` level.
    ReadEntry,
    /// `PRAGMA synchronous=FULL`.
    SetFull,
    /// The read-back of `FULL`.
    ReadBackFull,
    /// The restore of the entry level.
    Restore,
    /// The read-back of the restored level.
    ReadBackRestore,
    /// A `COMMIT` that fails and leaves the transaction open.
    #[cfg(test)]
    Commit,
    /// A `COMMIT` that succeeds but reports failure: a lost acknowledgement.
    #[cfg(test)]
    LostAcknowledgement,
    /// A `ROLLBACK` that never runs, leaving the transaction open.
    #[cfg(test)]
    Rollback,
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: the one durability step that fails on this thread.
    static FAULT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
    /// Test-only evidence: the `synchronous` level read just before the last `COMMIT`.
    static LEVEL_AT_COMMIT: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn injected(step: Step) -> bool {
    FAULT.with(std::cell::Cell::get) == Some(step)
}

/// The statement text a durability step runs; a test replaces the injected step's text.
///
/// A replaced read-back reads a value that is never a level; every other replaced statement
/// does not prepare, so it fails without changing anything.
#[cfg(test)]
fn step_sql(step: Step, sql: String) -> String {
    if !injected(step) {
        return sql;
    }
    match step {
        Step::ReadBackFull => "SELECT -1".to_owned(),
        _ => "SELECT RAISE(ABORT, 'injected')".to_owned(),
    }
}

// The test variant reads a thread-local, so the two variants share one non-const signature.
#[cfg(not(test))]
#[allow(clippy::missing_const_for_fn)]
fn step_sql(_step: Step, sql: String) -> String {
    sql
}

fn read_level(connection: &Connection, step: Step) -> rusqlite::Result<i64> {
    connection.query_row(
        &step_sql(step, "PRAGMA synchronous".to_owned()),
        [],
        |row| row.get(0),
    )
}

fn require_wal(connection: &Connection) -> RegistryResult<()> {
    let mode = connection
        .query_row(
            &step_sql(Step::ReadJournal, "PRAGMA journal_mode".to_owned()),
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| storage_error(&error))?;
    if mode == "wal" {
        Ok(())
    } else {
        Err(PluginTrustPolicyRegistryErrorV1::WalRequired)
    }
}

/// Set `synchronous=FULL` and read it back; either failure leaves the outcome unknown.
fn set_full(connection: &Connection) -> RegistryResult<()> {
    let full = connection
        .execute_batch(&step_sql(
            Step::SetFull,
            "PRAGMA synchronous=FULL".to_owned(),
        ))
        .and_then(|()| read_level(connection, Step::ReadBackFull))
        .is_ok_and(|level| level == SYNCHRONOUS_FULL);
    if full {
        Ok(())
    } else {
        Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)
    }
}

/// Whether `level` is the connection's level again, in autocommit, as read back.
fn restore(connection: &Connection, level: i64) -> bool {
    connection.is_autocommit()
        && connection
            .execute_batch(&step_sql(
                Step::Restore,
                format!("PRAGMA synchronous={level}"),
            ))
            .and_then(|()| read_level(connection, Step::ReadBackRestore))
            .is_ok_and(|read| read == level)
}

fn begin(connection: &Connection) -> RegistryResult<()> {
    connection
        .execute_batch(super::begin_immediate_sql())
        .map_err(|error| storage_error(&error))
}

#[cfg(not(test))]
fn commit(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("COMMIT")
}

#[cfg(test)]
fn commit(connection: &Connection) -> rusqlite::Result<()> {
    LEVEL_AT_COMMIT.with(|level| {
        level.set(
            connection
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .ok(),
        );
    });
    if injected(Step::Commit) {
        connection.execute_batch("SELECT RAISE(ABORT, 'injected')")
    } else if injected(Step::LostAcknowledgement) {
        connection
            .execute_batch("COMMIT")
            .and(Err(rusqlite::Error::InvalidQuery))
    } else {
        connection.execute_batch("COMMIT")
    }
}

/// Roll back whatever is open and report whether the connection is in autocommit afterwards.
///
/// Without an open transaction the reported error carries no information: `SQLite` may already
/// have rolled the transaction back.
fn rollback_to_autocommit(connection: &Connection) -> bool {
    #[cfg(test)]
    if injected(Step::Rollback) {
        return connection.is_autocommit();
    }
    drop(connection.execute_batch("ROLLBACK"));
    connection.is_autocommit()
}

/// The shared decision logic's view of the open transaction.
struct SqliteTransactionV1<'a> {
    connection: &'a Connection,
}

impl PluginTrustTransactionV1 for SqliteTransactionV1<'_> {
    fn scope(&self, scope: &str) -> RegistryResult<Option<RetainedScopeV1>> {
        rows::load_scope(self.connection, scope)
    }

    fn decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
        rows::load_decision(self.connection, scope, pmf1_digest)
    }

    fn active(&self, scope: &str, plugin_id: &str) -> RegistryResult<Option<ActiveReleaseV1>> {
        rows::load_active(self.connection, scope, plugin_id)
    }

    fn latest_release_row(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> RegistryResult<Option<PluginTrustLedgerRowV1>> {
        rows::load_latest_release_row(self.connection, scope, plugin_id)
    }

    fn next_row_seq(&self, scope: &str) -> RegistryResult<u64> {
        rows::next_row_seq(self.connection, scope)
    }
}

impl SqliteStore {
    /// Step P: a poisoned handle fails every registry call.
    const fn ensure_plugin_trust_usable(&self) -> RegistryResult<()> {
        if self.plugin_trust_poisoned.get() {
            Err(PluginTrustPolicyRegistryErrorV1::StorePoisoned)
        } else {
            Ok(())
        }
    }

    /// Record a failed restore: the connection's level is unknown until the store is reopened.
    fn poison_plugin_trust(&self) {
        self.plugin_trust_poisoned.set(true);
    }

    /// Restore the recorded `synchronous` level, or poison the handle.
    fn restore_level(&self, level: i64) -> RegistryResult<()> {
        if restore(&self.conn, level) {
            Ok(())
        } else {
            self.poison_plugin_trust();
            Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)
        }
    }

    /// Step T up to and including `BEGIN IMMEDIATE`; returns the level to restore.
    fn enter_full_durability(&self) -> RegistryResult<i64> {
        let connection = &self.conn;
        if !connection.is_autocommit() {
            return Err(PluginTrustPolicyRegistryErrorV1::NestedTransaction);
        }
        require_wal(connection)?;
        let entry =
            read_level(connection, Step::ReadEntry).map_err(|error| storage_error(&error))?;
        set_full(connection)
            .and_then(|()| begin(connection))
            .or_else(|error| self.restore_level(entry).and(Err(error)))
            .map(|()| entry)
    }

    /// Roll back, then restore the recorded level.
    ///
    /// A connection that is still inside a transaction after `ROLLBACK` cannot change its level:
    /// the handle is poisoned instead.
    fn abandon_and_restore(&self, level: i64) -> RegistryResult<()> {
        if rollback_to_autocommit(&self.conn) {
            self.restore_level(level)
        } else {
            self.poison_plugin_trust();
            Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)
        }
    }

    /// `COMMIT`, then restore the recorded level. A failed `COMMIT` is an unknown outcome.
    fn commit_and_restore(&self, level: i64) -> RegistryResult<()> {
        match commit(&self.conn) {
            Ok(()) => self.restore_level(level),
            Err(_) => self
                .abandon_and_restore(level)
                .and(Err(PluginTrustPolicyRegistryErrorV1::StorageIndeterminate)),
        }
    }

    /// Run `work` in one `BEGIN IMMEDIATE` transaction at `synchronous=FULL`.
    fn plugin_trust_transaction<T>(
        &self,
        work: &impl Fn(&Self) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.ensure_plugin_trust_usable()?;
        let level = self.enter_full_durability()?;
        match work(self) {
            Ok(value) => self.commit_and_restore(level).map(|()| value),
            Err(error) => self.abandon_and_restore(level).and(Err(error)),
        }
    }

    /// Run `work` as a transaction inside the erasure fence of the activation Timeline.
    ///
    /// The fence is entered before `BEGIN IMMEDIATE` and held through `COMMIT` and the
    /// durability restore. A missing gate or a refused fence is `ActivationEventRejected`.
    fn plugin_trust_event_transaction<T>(
        &mut self,
        timeline: TimelineId,
        work: &impl Fn(&Self) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.ensure_plugin_trust_usable()?;
        let fenced =
            self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
                Ok(store.plugin_trust_transaction(work))
            });
        fenced
            .or(Err(
                PluginTrustPolicyRegistryErrorV1::ActivationEventRejected,
            ))
            .and_then(std::convert::identity)
    }

    /// Append the activation Event under the guards of `EventStore::append`.
    ///
    /// The adapter computes `BLAKE3-256(payload)` itself and requires the store's own payload
    /// hash to equal it, so a store with another hasher can never activate.
    fn append_activation_event(
        &self,
        activation: &ActivationEventInputV1,
    ) -> RegistryResult<ActivationEventIdentityV1> {
        let timeline = activation.timeline;
        let payload_digest = activation.payload_digest();
        if *self
            .hasher
            .hash_payload(&activation.draft.payload)
            .as_bytes()
            != payload_digest
        {
            return Err(PluginTrustPolicyRegistryErrorV1::ActivationEventRejected);
        }
        // Appending exactly one draft yields exactly one Event, so a single `ok_or` covers both a
        // refused append and the (impossible) empty result.
        let appended = self
            .guarded_generic_append(timeline, std::slice::from_ref(&activation.draft))
            .ok()
            .and_then(|events| events.into_iter().next());
        appended
            .map(|event| ActivationEventIdentityV1::from_event(timeline, &event, payload_digest))
            .ok_or(PluginTrustPolicyRegistryErrorV1::ActivationEventRejected)
    }

    fn provision_in_transaction(
        &self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> RegistryResult<ProvisionOutcomeV1> {
        let connection = &self.conn;
        schema::ensure_for_provision(connection)?;
        let transaction = SqliteTransactionV1 { connection };
        match plan_provision(&transaction, anchor, tps1_bytes)? {
            None => Ok(ProvisionOutcomeV1::Unchanged),
            Some(write) => {
                rows::insert_scope(connection, &write.scope)?;
                rows::insert_ledger(connection, anchor.scope(), &write.row)?;
                Ok(ProvisionOutcomeV1::Created)
            }
        }
    }

    fn advance_in_transaction(
        &self,
        input: &PolicyInputV1<'_>,
    ) -> RegistryResult<PolicyAdvanceOutcomeV1> {
        let connection = &self.conn;
        schema::require_present(connection)?;
        let transaction = SqliteTransactionV1 { connection };
        let plan = plan_advance(&transaction, input)?;
        let scope = input.anchor.scope();
        write_advance(connection, scope, &plan)?;
        Ok(plan.outcome)
    }

    fn admit_in_transaction(
        &self,
        input: &PolicyInputV1<'_>,
        projection: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
    ) -> RegistryResult<AdmittedPluginReleaseReceiptV1> {
        let connection = &self.conn;
        schema::require_present(connection)?;
        let scope = input.anchor.scope();
        let transaction = SqliteTransactionV1 { connection };
        match plan_admit(&transaction, input, projection, activation)? {
            AdmitPlanV1::Replay(decision) => rows::raise_utc(connection, scope, input.utc.as_i64())
                .map(|()| AdmittedPluginReleaseReceiptV1 {
                    decision: *decision,
                    outcome: PluginTrustCommitOutcomeV1::IdempotentReplay,
                }),
            AdmitPlanV1::Commit(commit) => {
                let writes = commit.finish(self.append_activation_event(activation)?);
                rows::apply_policy(connection, scope, &writes.policy)?;
                rows::insert_decision(connection, &writes.decision)?;
                rows::upsert_active(connection, &writes.active)?;
                rows::insert_ledger(connection, scope, &writes.row)?;
                Ok(AdmittedPluginReleaseReceiptV1 {
                    decision: writes.decision,
                    outcome: PluginTrustCommitOutcomeV1::Committed,
                })
            }
        }
    }

    fn rollback_in_transaction(
        &self,
        input: &PolicyInputV1<'_>,
        target: &ValidatedPluginManifestProjectionV1,
        activation: &ActivationEventInputV1,
    ) -> RegistryResult<PluginRollbackReceiptV1> {
        let connection = &self.conn;
        schema::require_present(connection)?;
        let scope = input.anchor.scope();
        let transaction = SqliteTransactionV1 { connection };
        match plan_rollback(&transaction, input, target, activation)? {
            RollbackPlanV1::Replay(facts) => rows::raise_utc(connection, scope, input.utc.as_i64())
                .map(|()| PluginRollbackReceiptV1 {
                    facts: *facts,
                    outcome: PluginTrustCommitOutcomeV1::IdempotentReplay,
                }),
            RollbackPlanV1::Commit(commit) => {
                let writes = commit.finish(self.append_activation_event(activation)?);
                rows::apply_policy(connection, scope, &writes.policy)?;
                rows::upsert_active(connection, &writes.active)?;
                rows::insert_ledger(connection, scope, &writes.row)?;
                Ok(PluginRollbackReceiptV1 {
                    facts: writes.facts,
                    outcome: PluginTrustCommitOutcomeV1::Committed,
                })
            }
        }
    }

    /// Run a read on the validated schema; a poisoned handle fails first.
    fn plugin_trust_read<T>(
        &self,
        read: impl FnOnce(&Connection) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.ensure_plugin_trust_usable()?;
        schema::require_present(&self.conn)?;
        read(&self.conn)
    }
}

/// Write the policy change of one `advance_policy`, and its ledger row when there is one.
fn write_advance(connection: &Connection, scope: &str, plan: &AdvancePlanV1) -> RegistryResult<()> {
    rows::apply_policy(connection, scope, &plan.write)?;
    plan.row
        .as_ref()
        .map_or(Ok(()), |row| rows::insert_ledger(connection, scope, row))
}

/// `MissingState` unless the scope row exists.
fn require_scope(connection: &Connection, scope: &str) -> RegistryResult<()> {
    if rows::scope_exists(connection, scope)? {
        Ok(())
    } else {
        Err(PluginTrustPolicyRegistryErrorV1::MissingState)
    }
}

impl PluginTrustPolicyRegistryV1 for SqliteStore {
    fn provision(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
    ) -> RegistryResult<ProvisionOutcomeV1> {
        self.plugin_trust_transaction(&|store: &Self| {
            store.provision_in_transaction(anchor, tps1_bytes)
        })
    }

    fn admit(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> RegistryResult<AdmittedPluginReleaseReceiptV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.plugin_trust_event_transaction(activation.timeline, &|store: &Self| {
            store.admit_in_transaction(&input, projection, &activation)
        })
    }

    fn advance_policy(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> RegistryResult<PolicyAdvanceOutcomeV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.plugin_trust_transaction(&|store: &Self| store.advance_in_transaction(&input))
    }

    fn rollback(
        &mut self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        target: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
        activation: ActivationEventInputV1,
    ) -> RegistryResult<PluginRollbackReceiptV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.plugin_trust_event_transaction(activation.timeline, &|store: &Self| {
            store.rollback_in_transaction(&input, target, &activation)
        })
    }

    fn retained_release_decision(
        &self,
        scope: &str,
        pmf1_digest: [u8; 32],
    ) -> RegistryResult<Option<RetainedReleaseDecisionV1>> {
        self.plugin_trust_read(|connection| {
            require_scope(connection, scope)?;
            rows::load_decision(connection, scope, pmf1_digest)
        })
    }

    fn active_release(
        &self,
        scope: &str,
        plugin_id: &str,
    ) -> RegistryResult<Option<ActiveReleaseV1>> {
        self.plugin_trust_read(|connection| {
            require_scope(connection, scope)?;
            rows::load_active(connection, scope, plugin_id)
        })
    }

    fn retained_policy_state(&self, scope: &str) -> RegistryResult<RetainedPolicyStateV1> {
        self.plugin_trust_read(|connection| {
            let policy = rows::load_scope(connection, scope)?
                .ok_or(PluginTrustPolicyRegistryErrorV1::MissingState)?
                .policy;
            PluginFloorStateV1::from_retained(policy.ptr1_floor, policy.prv1_floor)
                .or(Err(PluginTrustPolicyRegistryErrorV1::CorruptState))
                .map(|_| policy)
        })
    }

    fn ledger(&self, scope: &str) -> RegistryResult<Vec<PluginTrustLedgerRowV1>> {
        self.plugin_trust_read(|connection| {
            require_scope(connection, scope)?;
            rows::load_ledger(connection, scope)
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "plugin_trust_registry_tests.rs"]
mod tests;
