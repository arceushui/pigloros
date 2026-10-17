//! `MemoryStore` adapter for the ADR-119 composition fallback registry port.
//!
//! The registry state is one more `MemoryStore` field, so a declaration or activation Event
//! shares the store's single mutable owner with the row it changes. Every operation plans from
//! the committed state first, appends its Event as the last fallible step, and only then
//! performs infallible assignments: a refused append leaves the state unchanged.
//!
//! The Event append runs under the same guards, in the same order, as `EventStore::append`: the
//! erasure fence of the target Timeline is the outermost scope, then the non-geographic draft,
//! fork, and visibility guards, then the append itself. The fold reads the Timeline inside that
//! fence.

use std::collections::BTreeMap;

use pos_core::store::SeqRange;
use pos_core::{ErasureProtectedOperationV1, Event, EventDraft, Hash, Seq, TimelineId};

use super::MemoryStore;
use crate::composition_fallback_registry::logic::{
    event_identity, payload_digest, plan_activate, plan_declare, require, FallbackCommitV1,
    FallbackPlanV1, FallbackReadsV1, FallbackResult,
};
use crate::composition_fallback_registry::{
    CompositionFallbackRegistryErrorV1 as Error, CompositionFallbackRegistryV1,
    FallbackActivateRequestV1, FallbackCommitOutcomeV1, FallbackCommitReceiptV1,
    FallbackDeclareRequestV1, FallbackEventIdentityV1, FallbackLedgerRowV1,
    FallbackProvisionOutcomeV1, FallbackRegistryRowV1,
};

type RowKey = (String, TimelineId);

/// The registry state of one `MemoryStore`.
#[derive(Default)]
pub(super) struct MemoryCompositionFallbackStateV1 {
    provisioned: bool,
    rows: BTreeMap<RowKey, FallbackRegistryRowV1>,
    policies: BTreeMap<Hash, Vec<u8>>,
    ledgers: BTreeMap<RowKey, Vec<FallbackLedgerRowV1>>,
}

impl MemoryCompositionFallbackStateV1 {
    const fn require_provisioned(&self) -> FallbackResult<()> {
        require(self.provisioned, Error::MissingState)
    }

    fn ledger(&self, scope: &str, timeline: TimelineId) -> Vec<FallbackLedgerRowV1> {
        self.ledgers
            .get(&(scope.to_owned(), timeline))
            .cloned()
            .unwrap_or_default()
    }

    fn commit(
        &mut self,
        scope: &str,
        timeline: TimelineId,
        commit: FallbackCommitV1,
        row: FallbackLedgerRowV1,
    ) {
        let key = (scope.to_owned(), timeline);
        self.policies.extend(commit.policy);
        self.rows.insert(key.clone(), commit.row);
        self.ledgers.entry(key).or_default().push(row);
    }
}

/// The logic's view of a `MemoryStore`; private, so no caller reads Events through it.
struct MemoryFallbackViewV1<'a> {
    store: &'a MemoryStore,
}

impl FallbackReadsV1 for MemoryFallbackViewV1<'_> {
    fn stored_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>> {
        let key = (scope.to_owned(), timeline);
        Ok(self.store.composition_fallback.rows.get(&key).cloned())
    }

    fn stored_policy(&self, policy_digest: Hash) -> FallbackResult<Option<Vec<u8>>> {
        let policies = &self.store.composition_fallback.policies;
        Ok(policies.get(&policy_digest).cloned())
    }

    fn stored_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
        Ok(self.store.composition_fallback.ledger(scope, timeline))
    }

    fn timeline_events(&self, timeline: TimelineId) -> FallbackResult<Vec<Event>> {
        self.store
            .collect_events_in_range(timeline, SeqRange::all())
            .or(Err(Error::TimelineUnavailable))
    }

    fn timeline_head(&self, timeline: TimelineId) -> FallbackResult<Seq> {
        self.store
            .logical_head_unchecked(timeline)
            .or(Err(Error::TimelineUnavailable))
    }
}

impl MemoryStore {
    /// Append the declaration or activation Event under the guards of `EventStore::append`.
    ///
    /// The caller holds the erasure fence. The store's own payload hash must equal
    /// `BLAKE3-256(payload)`, so a store with another hasher never commits.
    fn append_fallback_event(
        &mut self,
        timeline: TimelineId,
        draft: &EventDraft,
    ) -> FallbackResult<FallbackEventIdentityV1> {
        let digest = payload_digest(self.hasher.as_ref(), draft)?;
        let appended = self.guarded_generic_append(timeline, std::slice::from_ref(draft));
        event_identity(appended, digest)
    }

    /// Write the plan: return a replay, or append the Event and then commit the rows.
    fn write_fallback_plan(
        &mut self,
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
                let receipt = FallbackCommitReceiptV1 {
                    row: row.clone(),
                    outcome: FallbackCommitOutcomeV1::Committed,
                };
                self.composition_fallback
                    .commit(scope, timeline, *commit, row);
                Ok(receipt)
            }
        }
    }

    /// Plan one operation from the committed state, then write it.
    fn plan_and_write_fallback(
        &mut self,
        scope: &str,
        timeline: TimelineId,
        plan: &impl Fn(&dyn FallbackReadsV1) -> FallbackResult<FallbackPlanV1>,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        let planned = plan(&MemoryFallbackViewV1 { store: self })?;
        self.write_fallback_plan(scope, timeline, planned)
    }

    /// Plan and write one operation inside the erasure fence of its target Timeline.
    ///
    /// A missing gate or a refused fence is `EventRejected`.
    fn fenced_fallback_operation(
        &mut self,
        scope: &str,
        timeline: TimelineId,
        plan: impl Fn(&dyn FallbackReadsV1) -> FallbackResult<FallbackPlanV1>,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        self.composition_fallback.require_provisioned()?;
        let append = ErasureProtectedOperationV1::Append;
        let fenced = self.with_erasure_fence(timeline, append, |store| {
            Ok(store.plan_and_write_fallback(scope, timeline, &plan))
        });
        fenced
            .or(Err(Error::EventRejected))
            .and_then(std::convert::identity)
    }
}

impl CompositionFallbackRegistryV1 for MemoryStore {
    fn provision_fallback_registry(&mut self) -> FallbackResult<FallbackProvisionOutcomeV1> {
        let state = &mut self.composition_fallback;
        let outcome = if state.provisioned {
            FallbackProvisionOutcomeV1::Unchanged
        } else {
            FallbackProvisionOutcomeV1::Created
        };
        state.provisioned = true;
        Ok(outcome)
    }

    fn declare(
        &mut self,
        request: &FallbackDeclareRequestV1,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        let timeline = request.target.timeline;
        self.fenced_fallback_operation(&request.scope, timeline, |reads| {
            plan_declare(reads, request)
        })
    }

    fn activate(
        &mut self,
        request: &FallbackActivateRequestV1,
    ) -> FallbackResult<FallbackCommitReceiptV1> {
        let timeline = request.target.timeline;
        self.fenced_fallback_operation(&request.scope, timeline, |reads| {
            plan_activate(reads, request)
        })
    }

    fn registry_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>> {
        self.composition_fallback.require_provisioned()?;
        MemoryFallbackViewV1 { store: self }.stored_row(scope, timeline)
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
        self.composition_fallback.require_provisioned()?;
        MemoryFallbackViewV1 { store: self }.stored_policy(policy_digest)
    }

    fn fallback_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
        self.composition_fallback
            .require_provisioned()
            .map(|()| self.composition_fallback.ledger(scope, timeline))
    }
}
