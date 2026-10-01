//! `MemoryStore` adapter for the ADR-021 admitted-batch port.
//!
//! The adapter stages a complete batch on a clone of the target Timeline state
//! and installs it only after every fallible step succeeds. Cloning the full
//! per-Timeline state is acceptable here: `MemoryStore` is the unindexed
//! in-process reference adapter for tests and benchmarks, its admitted batches
//! are bounded by `MAX_PIPELINE_DRAFTS_PER_BATCH`, and the clone is the
//! simplest way to make every pre-install failure leave no partial state.

use std::num::NonZeroUsize;

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    error::CoreError,
    event::Event,
    ids::TimelineId,
    store::{checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, PurgeOutcome},
    ErasureProtectedOperationV1, PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptIdV1, PipelineOutcomeV1,
    PipelineReceiptLookupV1,
};

use super::MemoryStore;
use crate::{
    committed_pipeline_receipt, evaluate_pipeline_admission, install_or_reject,
    recovered_pipeline_receipt, retained_pipeline_receipt, PipelinePersistedStateV1,
};

#[cfg(test)]
thread_local! {
    /// Test-only fault injected after staging and before installing a batch.
    static FAIL_NEXT_PIPELINE_INSTALL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Retained exact-retry state for one committed admitted batch.
#[derive(Clone, Copy)]
pub(super) struct PipelineReceiptRecordV1 {
    timeline: TimelineId,
    /// Subject-scoped cleanup group shared with append identities.
    pub(super) scope: AppendDedupScope,
    pub(super) expires_at: WallTime,
    attempt_id: PipelineAttemptIdV1,
    basis_digest: Hash,
    draft_batch_digest: Hash,
    first_local_seq: u64,
    event_count: usize,
}

impl MemoryStore {
    /// Remove admission state owned by a deleted Timeline.
    pub(super) fn forget_pipeline_admission_timeline(&mut self, timeline: TimelineId) {
        self.pipeline_admission_fences.remove(&timeline);
        self.pipeline_admission_receipts
            .retain(|_, record| record.timeline != timeline);
    }

    fn admit_visible_pipeline_batch(
        &mut self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let key = basis.attempt().idempotency().dedup_key;
        // An expired receipt stays retained until a successful install
        // replaces it, so every rejection leaves the receipts unchanged.
        match self.pipeline_admission_receipts.get(&key).copied() {
            Some(record) if record.expires_at > now => {
                self.recover_pipeline_receipt(timeline, basis, record)
            }
            Some(_) | None => self.commit_pipeline_batch(timeline, basis, now),
        }
    }

    fn recover_pipeline_receipt(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        record: PipelineReceiptRecordV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        if record.timeline != timeline || record.basis_digest != basis.digest() {
            return Ok(PipelineOutcomeV1::AdmissionConflict);
        }
        self.retained_pipeline_events(timeline, record)
            .and_then(|events| recovered_pipeline_receipt(basis, timeline, &events))
    }

    /// The committed logical Events a retained receipt record names.
    fn retained_pipeline_events(
        &self,
        timeline: TimelineId,
        record: PipelineReceiptRecordV1,
    ) -> Result<Vec<Event>, CoreError> {
        self.logical_prefix(timeline).and_then(|prefix| {
            self.state(timeline)
                .events
                .iter()
                .skip_while(|event| event.seq.as_u64() < record.first_local_seq)
                .take(record.event_count)
                .map(|event| Self::logical_event(prefix, event.clone()))
                .collect::<Result<Vec<_>, _>>()
        })
    }

    /// Resolve a basis-free receipt lookup for one visible Timeline.
    fn lookup_visible_pipeline_receipt(
        &self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
        now: WallTime,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        match self.pipeline_admission_receipts.get(&key).copied() {
            Some(record) if record.expires_at > now => {
                if record.timeline != timeline || record.attempt_id != attempt_id {
                    return Ok(PipelineReceiptLookupV1::Conflict);
                }
                self.retained_pipeline_events(timeline, record)
                    .and_then(|events| {
                        retained_pipeline_receipt(
                            attempt_id,
                            timeline,
                            record.draft_batch_digest,
                            &events,
                        )
                    })
            }
            Some(_) | None => Ok(PipelineReceiptLookupV1::Absent),
        }
    }

    fn commit_pipeline_batch(
        &mut self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let fence = self.pipeline_admission_fences.get(&timeline).copied();
        self.logical_prefix(timeline)
            .and_then(|prefix| {
                let owned_head = self.state(timeline).timeline.head.as_u64();
                crate::checked_logical_head(prefix, owned_head)
                    .map(|logical_head| (prefix, Seq::from_u64(logical_head)))
            })
            .and_then(|(prefix, logical_head)| {
                let persisted = PipelinePersistedStateV1 {
                    fence: fence.as_ref(),
                    logical_head,
                    erasure_inventory_generation: self.erasure_inventory_generation,
                };
                let evaluated = evaluate_pipeline_admission(basis, &persisted, |grant| {
                    self.authority_state.resolve(grant)
                });
                install_or_reject(evaluated, |next_fence| {
                    self.install_pipeline_batch(timeline, basis, now, prefix, next_fence)
                })
            })
    }

    /// Stage the complete batch on a copy of the Timeline, then install every
    /// effect together. A failure before installation leaves no partial state.
    fn install_pipeline_batch(
        &mut self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
        prefix: u64,
        next_fence: &PipelineAdmissionFenceV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let mut staged = self.state(timeline).clone();
        let first_local_seq = staged.timeline.head.next().as_u64();
        let hasher = self.hasher.as_ref();
        basis
            .batch()
            .drafts()
            .iter()
            .map(|draft| Self::append_one_to_state(&mut staged, draft, hasher))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|committed| {
                committed
                    .iter()
                    .map(|event| Self::logical_event(prefix, event.clone()))
                    .collect::<Result<Vec<Event>, _>>()
                    .and_then(|events| committed_pipeline_receipt(basis, timeline, &events))
                    .and_then(|receipt| {
                        staged_receipt_expiry(now)
                            .map(|expires_at| (committed, receipt, expires_at))
                    })
            })
            .map(|(committed, receipt, expires_at)| {
                self.event_ids
                    .extend(committed.iter().map(|event| event.id));
                self.timelines.insert(timeline, staged);
                self.pipeline_admission_fences.insert(timeline, *next_fence);
                self.pipeline_admission_receipts.insert(
                    basis.attempt().idempotency().dedup_key,
                    PipelineReceiptRecordV1 {
                        timeline,
                        scope: basis.attempt().idempotency().scope,
                        expires_at,
                        attempt_id: basis.attempt().attempt_id(),
                        basis_digest: basis.digest(),
                        draft_batch_digest: basis.batch().digest(),
                        first_local_seq,
                        event_count: committed.len(),
                    },
                );
                PipelineOutcomeV1::Committed(receipt)
            })
    }
}

/// Compute the retained receipt horizon, the last fallible step before a
/// staged batch is installed.
fn staged_receipt_expiry(now: WallTime) -> Result<WallTime, CoreError> {
    #[cfg(test)]
    if FAIL_NEXT_PIPELINE_INSTALL.with(|fail| fail.replace(false)) {
        return Err(CoreError::Storage(
            "injected admitted-batch install failure".to_owned(),
        ));
    }
    checked_append_identity_expires_at(now)
}

impl PipelineAdmissionFencePublisherV1 for MemoryStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store
                .ensure_generic_timeline_visibility(timeline)
                .map(|()| {
                    store.pipeline_admission_fences.insert(timeline, fence);
                })
        })
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        Ok(self.pipeline_admission_fences.get(&timeline).copied())
    }
}

impl PipelineAdmissionPortV1 for MemoryStore {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let timeline = basis.attempt().observation().timeline_id();
        self.clock.now().and_then(|now| {
            self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
                store
                    .ensure_generic_fork_append_is_rejected(timeline)
                    .and_then(|()| store.ensure_generic_timeline_visibility(timeline))
                    .and_then(|()| store.admit_visible_pipeline_batch(timeline, basis, now))
            })
        })
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.clock.now().and_then(|now| {
            self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
                store
                    .ensure_generic_timeline_visibility(timeline)
                    .and_then(|()| {
                        store.lookup_visible_pipeline_receipt(timeline, key, attempt_id, now)
                    })
            })
        })
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.clock.now().map(|now| {
            let mut expired = self
                .pipeline_admission_receipts
                .iter()
                .filter(|(_, record)| record.expires_at <= now)
                .map(|(key, record)| (record.expires_at, key.as_bytes()))
                .collect::<Vec<_>>();
            expired.sort_unstable();
            expired.truncate(limit.get());
            for (_, key) in &expired {
                self.pipeline_admission_receipts
                    .remove(&AppendDedupKey::from_keyed_hash(*key));
            }
            PurgeOutcome {
                removed: expired.len(),
                more_may_remain: expired.len() == limit.get(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pos_core::{
        AppendDedupScope, AppendIdentity, CanonicalBytes, EntityId, ErasureContainmentGateV1,
        EventDraft, EventStore, Kind, PipelineAdmissionBasisDraftV1, PipelineAttemptDraftV1,
        PipelineAttemptIdV1, PipelineAttemptV1, PipelineDraftBatchV1, PipelineEvidenceRefV1,
        PipelineIngressV1, PipelineObservationAnchorV1, PipelinePreconditionV1,
        PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, SeqRange,
        TentativePipelineResultV1, PIPELINE_CONTRACT_VERSION_V1,
    };
    use ulid::Ulid;

    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn basis(timeline: TimelineId) -> PipelineAdmissionBasisV1 {
        let attempt = ok(PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt_id: Some(ok(PipelineAttemptIdV1::try_new([1; 16]))),
            ingress: Some(PipelineIngressV1::ScheduledAiDriver),
            observation: Some(ok(PipelineObservationAnchorV1::try_new(
                timeline,
                Seq::ZERO,
                Hash::from_bytes([2; 32]),
            ))),
            idempotency: Some(AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([3; 32]),
                AppendDedupScope::from_keyed_hash([4; 32]),
            )),
        }));
        let drafts = (0..2_u8)
            .map(|index| {
                EventDraft::new(
                    EntityId::from_ulid(Ulid::from(9_u128)),
                    Kind::new("world.action"),
                    CanonicalBytes::from_vec(vec![index]),
                )
            })
            .collect();
        ok(PipelineAdmissionBasisV1::try_from_draft(
            PipelineAdmissionBasisDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt: Some(attempt),
                tentative_result: Some(TentativePipelineResultV1::AiProviderValidation(ok(
                    PipelineEvidenceRefV1::try_new(Hash::from_bytes([5; 32])),
                ))),
                precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(Seq::ZERO)),
                security_revisions: Some(ok(PipelineSecurityRevisionsV1::try_from_draft(
                    PipelineSecurityRevisionsDraftV1 {
                        authority: Hash::from_bytes([6; 32]),
                        consent: Hash::from_bytes([6; 32]),
                        capability: Hash::from_bytes([6; 32]),
                        delegation: Hash::from_bytes([6; 32]),
                        policy: Hash::from_bytes([6; 32]),
                        execution_profile: Hash::from_bytes([6; 32]),
                        erasure: Hash::from_bytes([6; 32]),
                    },
                ))),
                batch: Some(ok(PipelineDraftBatchV1::try_new(drafts))),
            },
        ))
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn injected_install_failure_leaves_no_partial_batch_or_receipt() {
        let mut store = MemoryStore::new();
        let timeline = ok(store.create_timeline("admission-fault")).id();
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        let basis = basis(timeline);
        let fence = ok(PipelineAdmissionFenceV1::try_new(
            Hash::from_bytes([7; 32]),
            basis.security_revisions(),
            None,
            10,
        ));
        ok(store.set_pipeline_admission_fence(timeline, fence));
        let staged_fence = ok(fence.after_commit(2).ok_or("budget"));

        FAIL_NEXT_PIPELINE_INSTALL.with(|fail| fail.set(true));
        let failure = store.install_pipeline_batch(
            timeline,
            &basis,
            WallTime::from_micros(1),
            0,
            &staged_fence,
        );

        assert!(failure.is_err());
        assert!(ok(store.read(timeline, SeqRange::all())).is_empty());
        assert_eq!(ok(store.pipeline_admission_fence(timeline)), Some(fence));
        assert!(store.pipeline_admission_receipts.is_empty());
        let retried = ok(store.install_pipeline_batch(
            timeline,
            &basis,
            WallTime::from_micros(1),
            0,
            &staged_fence,
        ));
        assert_eq!(ok(store.read(timeline, SeqRange::all())).len(), 2);
        assert_eq!(
            ok(store.pipeline_admission_fence(timeline)),
            Some(staged_fence)
        );
        let PipelineOutcomeV1::Committed(receipt) = retried else {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {retried:?}")));
        };
        assert_eq!(receipt.committed_events().len(), 2);
    }
}
