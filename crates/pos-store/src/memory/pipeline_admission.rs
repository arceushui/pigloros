//! `MemoryStore` adapter for the ADR-021 admitted-batch port.

use std::num::NonZeroUsize;

use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    error::CoreError,
    event::Event,
    ids::TimelineId,
    store::{checked_append_identity_expires_at, AppendDedupKey, PurgeOutcome},
    ErasureProtectedOperationV1, PipelineAdmissionBasisV1, PipelineAdmissionFenceV1,
    PipelineAdmissionPortV1, PipelineOutcomeV1,
};

use super::MemoryStore;

#[cfg(test)]
thread_local! {
    /// Test-only fault injected after staging and before installing a batch.
    static FAIL_NEXT_PIPELINE_INSTALL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Retained exact-retry state for one committed admitted batch.
#[derive(Clone, Copy)]
pub(super) struct PipelineReceiptRecordV1 {
    timeline: TimelineId,
    basis_digest: Hash,
    first_local_seq: u64,
    event_count: usize,
    expires_at: WallTime,
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
        match self.pipeline_admission_receipts.get(&key).copied() {
            Some(record) if record.expires_at > now => {
                self.recover_pipeline_receipt(timeline, basis, record)
            }
            Some(_) => {
                self.pipeline_admission_receipts.remove(&key);
                self.commit_pipeline_batch(timeline, basis, now)
            }
            None => self.commit_pipeline_batch(timeline, basis, now),
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
        self.logical_prefix(timeline)
            .and_then(|prefix| {
                self.state(timeline)
                    .events
                    .iter()
                    .skip_while(|event| event.seq.as_u64() < record.first_local_seq)
                    .take(record.event_count)
                    .map(|event| Self::logical_event(prefix, event.clone()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|events| crate::recovered_pipeline_receipt(basis, timeline, &events))
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
                crate::evaluate_pipeline_admission(basis, fence.as_ref(), logical_head, |grant| {
                    self.authority_state.resolve(grant)
                })
                .map_or_else(Ok, |next_fence| {
                    self.install_pipeline_batch(timeline, basis, now, prefix, &next_fence)
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
                    .and_then(|events| crate::committed_pipeline_receipt(basis, timeline, &events))
                    .and_then(|receipt| {
                        checked_append_identity_expires_at(now)
                            .map(|expires_at| (committed, receipt, expires_at))
                    })
            })
            .and_then(|(committed, receipt, expires_at)| {
                #[cfg(test)]
                if FAIL_NEXT_PIPELINE_INSTALL.with(|fail| fail.replace(false)) {
                    return Err(CoreError::Storage(
                        "injected admitted-batch install failure".to_owned(),
                    ));
                }
                self.event_ids
                    .extend(committed.iter().map(|event| event.id));
                self.timelines.insert(timeline, staged);
                self.pipeline_admission_fences.insert(timeline, *next_fence);
                self.pipeline_admission_receipts.insert(
                    basis.attempt().idempotency().dedup_key,
                    PipelineReceiptRecordV1 {
                        timeline,
                        basis_digest: basis.digest(),
                        first_local_seq,
                        event_count: committed.len(),
                        expires_at,
                    },
                );
                Ok(PipelineOutcomeV1::Committed(receipt))
            })
    }
}

impl PipelineAdmissionPortV1 for MemoryStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.ensure_generic_timeline_visibility(timeline).map(|()| {
            self.pipeline_admission_fences.insert(timeline, fence);
        })
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        Ok(self.pipeline_admission_fences.get(&timeline).copied())
    }

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
        assert!(matches!(
            store.install_pipeline_batch(
                timeline,
                &basis,
                WallTime::from_micros(1),
                0,
                &staged_fence
            ),
            Ok(PipelineOutcomeV1::Committed(_))
        ));
        assert_eq!(ok(store.read(timeline, SeqRange::all())).len(), 2);
    }
}
