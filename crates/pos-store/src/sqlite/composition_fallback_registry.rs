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
//! transaction. A write runs the durability protocol of `super::registry_durability`, shared
//! with the Plugin trust registry. For `declare` and `activate`, the erasure fence of the target
//! Timeline (`EventRejected`) is taken after the poison check and encloses the rest of the
//! protocol, up to and including the durability restore.
//!
//! The Event is appended inside the open transaction through the same guard chain as
//! `EventStore::append` (`guarded_generic_append`), whose savepoint nests inside it. The fold
//! reads the target Timeline on the same connection inside the transaction.

use pos_core::store::SeqRange;
use pos_core::{ErasureProtectedOperationV1, Event, EventDraft, Hash, Seq, TimelineId};
use rusqlite::Connection;

use super::composition_fallback_registry_rows::{self as rows, storage_error};
use super::composition_fallback_registry_schema as schema;
use super::registry_durability::{DurabilityErrorV1, DurableRegistryV1};
use super::SqliteStore;
use crate::composition_fallback_registry::logic::{
    event_identity, payload_digest, plan_activate, plan_declare, FallbackPlanV1, FallbackReadsV1,
    FallbackResult,
};
use crate::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as Error, CompositionFallbackRegistryV1,
    FallbackActivateRequestV1, FallbackCommitOutcomeV1, FallbackCommitReceiptV1,
    FallbackDeclareRequestV1, FallbackEventIdentityV1, FallbackLedgerRowV1,
    FallbackProvisionOutcomeV1, FallbackRegistryRowV1,
};

#[cfg(test)]
use super::registry_durability::seam;

impl DurabilityErrorV1 for Error {
    const STORE_POISONED: Self = Self::StorePoisoned;
    const NESTED_TRANSACTION: Self = Self::NestedTransaction;
    const WAL_REQUIRED: Self = Self::WalRequired;
    const STORAGE_INDETERMINATE: Self = Self::StorageIndeterminate;

    fn storage(error: &rusqlite::Error) -> Self {
        storage_error(error)
    }
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
    /// The shared durability protocol on this handle's connection and fallback poison cell.
    const fn fallback_durability(&self) -> DurableRegistryV1<'_> {
        DurableRegistryV1 {
            connection: &self.conn,
            poisoned: &self.composition_fallback_poisoned,
        }
    }

    /// A poisoned handle fails every registry call.
    const fn ensure_fallback_usable(&self) -> FallbackResult<()> {
        self.fallback_durability().ensure_usable()
    }

    /// Run `work` in one `BEGIN IMMEDIATE` transaction at `synchronous=FULL`.
    fn fallback_transaction<T>(
        &self,
        work: &impl Fn(&Self) -> FallbackResult<T>,
    ) -> FallbackResult<T> {
        self.fallback_durability().transaction(|| work(self))
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
