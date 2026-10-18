//! `SQLite` adapter for the ADR-103 revisions 4 and 5 Plugin trust policy registry port.
//!
//! The adapter is `impl PluginTrustPolicyRegistryV1 for SqliteStore`, so the registry rows and
//! the activation Event share the store's one connection and one WAL database transaction. The
//! decisions themselves are the shared `plan_*` functions of
//! `crate::plugin_trust_registry::logic`; this file only reads and writes the plan through
//! [`SqliteTransactionV1`] and orders the locks.
//!
//! # Lock order and durability (decisions 3 and 7)
//!
//! Only the mutating operations run the protocol below. The single-statement reads
//! (`retained_release_decision`, `active_release`, `retained_policy_state`, `ledger`) run the
//! poison check and the schema check with no transaction. `evaluate_current_release` (revision 5)
//! is a read too, but it reads several rows that must agree, so it runs the poison check and then
//! one plain deferred `BEGIN` read transaction (`plugin_trust_read_transaction`).
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
//! A read transaction whose `ROLLBACK` leaves the connection inside that transaction poisons the
//! handle the same way, but returns the work's error (or `StorageFailed`), because nothing was
//! written.
//!
//! The write protocol from the poison check on, except the fence, is `super::registry_durability`,
//! which the composition fallback registry shares; the read transaction stays here.
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
use super::registry_durability::{
    committed, rollback_to_autocommit, DurabilityErrorV1, DurableRegistryV1,
};
use super::SqliteStore;
use crate::plugin_trust_registry::logic::{
    plan_admit, plan_advance, plan_evaluate, plan_provision, plan_rollback, AdmitPlanV1,
    AdvancePlanV1, PluginTrustTransactionV1, PolicyInputV1, RetainedScopeV1, RollbackPlanV1,
};
use crate::plugin_trust_registry::{
    ActivationEventIdentityV1, ActivationEventInputV1, ActiveReleaseV1,
    AdmittedPluginReleaseReceiptV1, CurrentReleaseEvaluationV1, PluginRollbackReceiptV1,
    PluginTrustCommitOutcomeV1, PluginTrustLedgerRowV1, PluginTrustPolicyRegistryErrorV1,
    PluginTrustPolicyRegistryV1, PolicyAdvanceOutcomeV1, ProvisionOutcomeV1, RetainedPolicyStateV1,
    RetainedReleaseDecisionV1, TrustedUtcSecondV1,
};

impl DurabilityErrorV1 for PluginTrustPolicyRegistryErrorV1 {
    const STORE_POISONED: Self = Self::StorePoisoned;
    const NESTED_TRANSACTION: Self = Self::NestedTransaction;
    const WAL_REQUIRED: Self = Self::WalRequired;
    const STORAGE_INDETERMINATE: Self = Self::StorageIndeterminate;

    fn storage(error: &rusqlite::Error) -> Self {
        storage_error(error)
    }
}

/// The test seam: the shared durability seam, plus the snapshot probe of the evaluation's read
/// transaction, which only this registry has.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod seam {
    use std::cell::RefCell;

    pub(super) use crate::sqlite::registry_durability::seam::{
        Step, FAULT, LEVEL_AT_COMMIT, RESTORE_PROBE,
    };

    thread_local! {
        /// Runs inside an evaluation's read transaction, right after its schema check, so a
        /// test can commit a write through a second handle after the snapshot began.
        pub(super) static SNAPSHOT_PROBE: RefCell<Option<Box<dyn Fn()>>> =
            const { RefCell::new(None) };
    }

    pub(super) fn snapshot_probe() {
        SNAPSHOT_PROBE.with(|probe| {
            if let Some(probe) = probe.borrow().as_ref() {
                probe();
            }
        });
    }
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
    /// The shared durability protocol on this handle's connection and trust poison cell.
    const fn plugin_trust_durability(&self) -> DurableRegistryV1<'_> {
        DurableRegistryV1 {
            connection: &self.conn,
            poisoned: &self.plugin_trust_poisoned,
        }
    }

    /// Step P: a poisoned handle fails every registry call.
    const fn ensure_plugin_trust_usable(&self) -> RegistryResult<()> {
        self.plugin_trust_durability().ensure_usable()
    }

    /// Run `work` in one `BEGIN IMMEDIATE` transaction at `synchronous=FULL` (step T).
    fn plugin_trust_transaction<T>(
        &self,
        work: &impl Fn(&Self) -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.plugin_trust_durability().transaction(|| work(self))
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
        // Step P precedes the fence by design: a poisoned handle reports `StorePoisoned` first.
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

    /// Roll back a read transaction's work, and poison the handle if the connection is still
    /// inside the transaction afterwards.
    ///
    /// The caller returns its own error; a failed `ROLLBACK` is ignored by
    /// `rollback_to_autocommit`.
    fn abandon_read(&self) {
        if !rollback_to_autocommit(&self.conn) {
            self.plugin_trust_durability().poison();
        }
    }

    /// `COMMIT` a read transaction. A failed `COMMIT` is `StorageFailed`: nothing was written,
    /// so there is no unknown outcome, and the transaction is rolled back like a failed work.
    fn finish_read<T>(&self, value: T) -> RegistryResult<T> {
        if committed(&self.conn) {
            Ok(value)
        } else {
            self.abandon_read();
            Err(PluginTrustPolicyRegistryErrorV1::StorageFailed)
        }
    }

    /// Run `work` in one plain deferred `BEGIN` read transaction, so every row it combines is one
    /// committed snapshot.
    ///
    /// Order: the poison check, then the `BEGIN` itself. Inside a caller's transaction the nested
    /// `BEGIN` fails with `StorageFailed` and no `ROLLBACK` is issued, because it would end the
    /// caller's transaction. A busy database surfaces at the first read, not at the `BEGIN`. No
    /// WAL requirement, no `synchronous` change, no `BEGIN IMMEDIATE`: a read-only handle works.
    fn plugin_trust_read_transaction<T>(
        &self,
        work: impl FnOnce() -> RegistryResult<T>,
    ) -> RegistryResult<T> {
        self.ensure_plugin_trust_usable()?;
        self.conn
            .execute_batch("BEGIN")
            .map_err(|error| storage_error(&error))?;
        match work() {
            Ok(value) => self.finish_read(value),
            Err(error) => {
                self.abandon_read();
                Err(error)
            }
        }
    }

    fn evaluate_in_read(
        &self,
        input: &PolicyInputV1<'_>,
        projection: &ValidatedPluginManifestProjectionV1,
    ) -> RegistryResult<CurrentReleaseEvaluationV1> {
        let connection = &self.conn;
        schema::require_present(connection)?;
        #[cfg(test)]
        seam::snapshot_probe();
        let transaction = SqliteTransactionV1 { connection };
        plan_evaluate(&transaction, input, projection)
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
    rows::scope_exists(connection, scope).and_then(|exists| {
        exists
            .then_some(())
            .ok_or(PluginTrustPolicyRegistryErrorV1::MissingState)
    })
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

    fn evaluate_current_release(
        &self,
        anchor: &PluginTrustPolicyAnchorV1,
        tps1_bytes: &[u8],
        evidence: &VerifiedPluginTrustEvidenceV1,
        projection: &ValidatedPluginManifestProjectionV1,
        trusted_utc: TrustedUtcSecondV1,
        tick: u64,
    ) -> RegistryResult<CurrentReleaseEvaluationV1> {
        let input = PolicyInputV1 {
            anchor,
            tps1_bytes,
            evidence,
            utc: trusted_utc,
            tick,
        };
        self.plugin_trust_read_transaction(|| self.evaluate_in_read(&input, projection))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "plugin_trust_registry_tests.rs"]
mod tests;
