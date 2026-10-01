//! ADR-021 host admission for one scheduled AI Driver pass.
//!
//! An anchored `step_all`/cadenced pass stages every due Driver against one
//! shared base snapshot. This module turns that complete staged pass into one
//! [`PipelineAdmissionBasisV1`] on the `ScheduledAiDriver` path and commits it
//! through the host-only [`PipelineAdmissionPortV1`]: the store compares the
//! basis and assigns Event identity and Timeline Order inside one transaction,
//! and staged Driver and cadence state commits only after that batch commits.
//!
//! A protected pass is admitted inside the consent authority's token fence,
//! so a consent revocation cannot interleave between the commit-time consent
//! recheck and the store transaction.

use pos_core::{
    AppendIdentity, CoreError, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1,
    PipelineAdmissionPortV1, PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1,
    PipelineCommitReceiptV1, PipelineContractErrorV1, PipelineDraftBatchV1, PipelineEvidenceRefV1,
    PipelineIngressV1, PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineSecurityRevisionsV1, Seq, TentativePipelineResultV1, PIPELINE_CONTRACT_VERSION_V1,
};

use super::{OperationContext, PendingStep, PluginRegistry};
use crate::error::RuntimeError;

/// Host-owned inputs that bind one staged scheduled pass to its admission basis.
///
/// Every field is issued by the trusted host, never by a Driver or provider:
/// the attempt and idempotency identities, the reference to the host's ADR-046
/// provider-validation evidence, the security revisions read from the
/// host-published admission fence when the pass was observed, and the Logical
/// Head and clock the host read after the pass finished. The observation
/// anchor itself is never the expected head, so an Event committed while the
/// pass ran does not by itself invalidate its shared base snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduledPassAdmissionV1 {
    pub attempt_id: PipelineAttemptIdV1,
    pub idempotency: AppendIdentity,
    pub provider_validation: PipelineEvidenceRefV1,
    pub security_revisions: PipelineSecurityRevisionsV1,
    pub commit_head: Seq,
    pub commit_now_secs: u64,
}

impl PluginRegistry {
    /// Admit and commit the staged scheduled pass through host admission.
    ///
    /// The complete staged draft vector keeps host Driver schedule order and
    /// each Driver's vector order. Staged Driver and cadence state commits
    /// only after the store commits the whole batch; an empty pass has no
    /// Event to admit and returns `Ok(None)` after the same consent recheck.
    ///
    /// # Errors
    /// Returns [`RuntimeError::PendingDriverStep`] when no pass is staged,
    /// [`RuntimeError::AuthorityFenceRequired`] for participant-authorized
    /// work, a consent, schema, or [`RuntimeError::PipelineContract`] error, a
    /// [`RuntimeError::ScheduledPassNotAdmitted`] outcome, or a store error.
    /// Every error aborts all staged Driver state and commits no Event, except
    /// [`pos_core::CoreError::StorageOutcomeUnknown`], which retains the exact
    /// basis for [`Self::recover_scheduled_pass`].
    pub fn admit_scheduled_pass(
        &mut self,
        port: &mut dyn PipelineAdmissionPortV1,
        admission: &ScheduledPassAdmissionV1,
    ) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let Some(pending) = self.pending_step.take() else {
            return Err(RuntimeError::PendingDriverStep);
        };
        // Only an anchored scheduled pass carries a base cut and snapshot
        // digest; participant-authorized work keeps its own authority fence.
        let Some((observed_through, snapshot_digest)) = pending.scheduled else {
            let _ = self.abort_drivers(&pending.driver_ids);
            return Err(RuntimeError::AuthorityFenceRequired);
        };
        let prepared = self
            .validate_operation(
                pending.timeline,
                &pending.operation,
                admission.commit_head,
                Some(admission.commit_now_secs),
            )
            .and_then(|()| {
                self.validate_protected_drafts(
                    pending.timeline,
                    &pending.operation,
                    admission.commit_head,
                    &pending.staged_drafts,
                )
            })
            .and_then(|()| self.schemas.validate_batch(&pending.staged_drafts))
            .and_then(|()| scheduled_basis(&pending, admission, observed_through, snapshot_digest));
        match prepared {
            Ok(Some(basis)) => self.finish_scheduled_admission(
                port,
                InDoubtAdmission {
                    pending,
                    basis,
                    commit_head: admission.commit_head,
                    commit_now_secs: admission.commit_now_secs,
                },
            ),
            Ok(None) => {
                self.commit_pending_step(pending);
                Ok(None)
            }
            Err(error) => {
                let _ = self.abort_drivers(&pending.driver_ids);
                Err(error)
            }
        }
    }

    /// Resolve an in-doubt scheduled pass by resubmitting its exact retained basis.
    ///
    /// Recovery never reruns a Driver or provider: the store either returns
    /// the original receipt for the committed batch or admits the identical
    /// basis once. A protected pass is resubmitted inside the same consent
    /// token fence, at the commit head and time of the original attempt.
    ///
    /// # Errors
    /// Returns [`RuntimeError::NoScheduledAdmissionInDoubt`] when nothing is
    /// in doubt, otherwise the same outcomes as [`Self::admit_scheduled_pass`].
    pub fn recover_scheduled_pass(
        &mut self,
        port: &mut dyn PipelineAdmissionPortV1,
    ) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        let Some(in_doubt) = self.in_doubt_admission.take() else {
            return Err(RuntimeError::NoScheduledAdmissionInDoubt);
        };
        self.finish_scheduled_admission(port, *in_doubt)
    }

    fn finish_scheduled_admission(
        &mut self,
        port: &mut dyn PipelineAdmissionPortV1,
        attempt: InDoubtAdmission,
    ) -> Result<Option<PipelineCommitReceiptV1>, RuntimeError> {
        match self.admit_within_consent_fence(port, &attempt) {
            Ok(
                PipelineOutcomeV1::Committed(receipt)
                | PipelineOutcomeV1::RecoveredDuplicate(receipt),
            ) => {
                self.commit_pending_step(attempt.pending);
                Ok(Some(receipt))
            }
            Err(error @ RuntimeError::Store(CoreError::StorageOutcomeUnknown(_))) => {
                self.in_doubt_admission = Some(Box::new(attempt));
                Err(error)
            }
            result => {
                let _ = self.abort_drivers(&attempt.pending.driver_ids);
                Err(result.map_or_else(std::convert::identity, not_admitted))
            }
        }
    }

    /// Submit the basis, holding the consent token fence for a protected pass.
    fn admit_within_consent_fence(
        &self,
        port: &mut dyn PipelineAdmissionPortV1,
        attempt: &InDoubtAdmission,
    ) -> Result<PipelineOutcomeV1, RuntimeError> {
        let mut admit = || {
            port.admit_pipeline_batch(&attempt.basis)
                .map_err(RuntimeError::Store)
        };
        match &attempt.pending.operation {
            OperationContext::Public => admit(),
            OperationContext::Protected { token, .. } => self.consent_gate.as_ref().map_or(
                Err(RuntimeError::ConsentOperationUnavailable),
                |gate| {
                    let mut outcome = Err(RuntimeError::ConsentOperationUnavailable);
                    let fenced = gate.with_token_fence(
                        attempt.pending.timeline,
                        token,
                        attempt.commit_head.as_u64(),
                        attempt.commit_now_secs,
                        &mut || outcome = admit(),
                    );
                    fenced.map_err(RuntimeError::Consent).and(outcome)
                },
            ),
        }
    }
}

/// One built scheduled-pass basis with the host inputs of its commit fence.
///
/// It is retained unchanged while the store outcome is unknown, so recovery
/// resubmits exactly the original attempt.
pub(super) struct InDoubtAdmission {
    pub(super) pending: PendingStep,
    basis: PipelineAdmissionBasisV1,
    commit_head: Seq,
    commit_now_secs: u64,
}

fn not_admitted(outcome: PipelineOutcomeV1) -> RuntimeError {
    RuntimeError::ScheduledPassNotAdmitted(Box::new(outcome))
}

/// Build the `ScheduledAiDriver` basis for a nonempty anchored scheduled pass.
fn scheduled_basis(
    pending: &PendingStep,
    admission: &ScheduledPassAdmissionV1,
    observed_through: Seq,
    snapshot_digest: pos_core::Hash,
) -> Result<Option<PipelineAdmissionBasisV1>, RuntimeError> {
    if pending.staged_drafts.is_empty() {
        return Ok(None);
    }
    build_basis(pending, admission, observed_through, snapshot_digest)
        .map(Some)
        .map_err(RuntimeError::PipelineContract)
}

fn build_basis(
    pending: &PendingStep,
    admission: &ScheduledPassAdmissionV1,
    observed_through: Seq,
    snapshot_digest: pos_core::Hash,
) -> Result<PipelineAdmissionBasisV1, PipelineContractErrorV1> {
    PipelineObservationAnchorV1::try_new(pending.timeline, observed_through, snapshot_digest)
        .and_then(|observation| {
            PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt_id: Some(admission.attempt_id),
                ingress: Some(PipelineIngressV1::ScheduledAiDriver),
                observation: Some(observation),
                idempotency: Some(admission.idempotency),
            })
        })
        .and_then(|attempt| {
            PipelineDraftBatchV1::try_new(pending.staged_drafts.clone())
                .map(|batch| (attempt, batch))
        })
        .and_then(|(attempt, batch)| {
            PipelineAdmissionBasisV1::try_from_draft(PipelineAdmissionBasisDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt: Some(attempt),
                tentative_result: Some(TentativePipelineResultV1::AiProviderValidation(
                    admission.provider_validation,
                )),
                precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(
                    admission.commit_head,
                )),
                security_revisions: Some(admission.security_revisions),
                batch: Some(batch),
            })
        })
}
