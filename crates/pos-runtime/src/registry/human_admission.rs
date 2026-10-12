//! ADR-021 host admission for one human `ProposedAction` (#319).
//!
//! A human request has already passed host authentication and Principal
//! authorization before it reaches this seam. The registry then:
//!
//! 1. looks up the retained receipt for the request's idempotency key, so an
//!    exact retry returns the committed receipt without rerunning domain
//!    approval and a reused key from another request is a typed conflict;
//! 2. runs the owning Plugin's ADR-057 `ActionApprover`, whose draft stays
//!    tentative;
//! 3. binds the attempt, its observation cursor, the host authorization and
//!    domain approval evidence, and the full security revision set into one
//!    [`PipelineAdmissionBasisV1`] on the `HumanProposedAction` path; and
//! 4. commits it through the host-only [`FactualAdmissionPortV1`], which
//!    compares the whole basis and assigns Event identity and Timeline Order
//!    at its serialization point.
//!
//! Only the store's committed receipt leaves this seam. A rejected attempt
//! commits no Event and is never re-observed or retried here.

use pos_core::{
    assemble_factual_tick, ensure_factual_set_headroom, pipeline_draft_vector_digest_v1,
    AppendIdentity, CoreError, EventDraft, FactualAdmissionPortV1, FactualDependencyErrorV1,
    FactualPrefixReadPortV1, FactualTickContextV1, FactualTickDependenciesV1, FactualTickShapeV1,
    Hash, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1, PipelineAttemptDraftV1,
    PipelineAttemptIdV1, PipelineAttemptV1, PipelineCommitReceiptV1, PipelineContractErrorV1,
    PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1, PipelineObservationAnchorV1,
    PipelineOutcomeV1, PipelinePreconditionV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsV1, ProposedAction, TentativePipelineResultV1, TimelineId,
    PIPELINE_CONTRACT_VERSION_V1,
};

use super::PluginRegistry;
use crate::error::ActionSubmissionError;

const APPROVAL_DOMAIN: &[u8] = b"PiglorOS.HumanDomainApproval.v1\0";

/// Host-owned inputs that bind one human action attempt to its admission basis.
///
/// The trusted host derives every field, never the caller or the
/// `ActionApprover`: the attempt and idempotency identities, the observation
/// cursor the request is valid against, a reference to the host's Principal
/// authorization evidence, the security revisions it published for the
/// Timeline, and the authority grant of its admission fence. The observation
/// cursor is also the expected Logical Head, so a committed Event after the
/// cursor makes the attempt stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanActionAdmissionV1 {
    pub attempt_id: PipelineAttemptIdV1,
    pub idempotency: AppendIdentity,
    pub observation: PipelineObservationAnchorV1,
    pub authorization: PipelineEvidenceRefV1,
    pub security_revisions: PipelineSecurityRevisionsV1,
    pub authority_grant: Hash,
}

/// Authoritative result of one admitted human action.
///
/// It carries only the store's committed receipt; the tentative approval
/// result never leaves the admission seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanActionReceiptV1 {
    receipt: PipelineCommitReceiptV1,
    recovered: bool,
}

impl HumanActionReceiptV1 {
    /// The committed receipt assigned by the store.
    #[must_use]
    pub const fn receipt(&self) -> &PipelineCommitReceiptV1 {
        &self.receipt
    }

    /// Whether this is the retained receipt of an earlier committed attempt.
    #[must_use]
    pub const fn recovered(&self) -> bool {
        self.recovered
    }
}

/// Typed failure of one human action attempt. None of them commits an Event.
#[derive(Debug, thiserror::Error)]
pub enum HumanActionAdmissionErrorV1 {
    /// The owning Plugin is missing, its `ActionApprover` denied the
    /// proposal, or the erasure fence rejected the approval.
    #[error(transparent)]
    Submission(#[from] ActionSubmissionError),
    /// Another attempt or Timeline holds the request's idempotency key.
    #[error("idempotency key is held by another attempt")]
    IdempotencyConflict,
    /// The store compared the basis and committed nothing.
    #[error("human action attempt was not admitted")]
    NotAdmitted(Box<PipelineOutcomeV1>),
    /// The approved draft cannot form a valid admission basis.
    #[error(transparent)]
    Contract(#[from] PipelineContractErrorV1),
    /// The trusted host could not derive its own admission inputs (attempt,
    /// observation, authorization evidence, or admission fence). This is a
    /// host fault, never a rejection of the proposal.
    #[error("host admission inputs are invalid: {0}")]
    HostContract(PipelineContractErrorV1),
    /// The dependency declaration of the action could not be built or
    /// checked.
    #[error(transparent)]
    DependencyDeclaration(FactualDependencyErrorV1),
    /// The store failed; an unknown commit outcome is recovered by retrying
    /// the same request, which only looks up its receipt.
    #[error(transparent)]
    Store(CoreError),
}

impl PluginRegistry {
    /// Admit one authorized human `ProposedAction` through host admission.
    ///
    /// The retained-receipt lookup runs first, so an exact retry returns the
    /// original receipt without invoking the `ActionApprover`. Otherwise the
    /// owning approver produces one tentative draft, which commits only if
    /// the store accepts the complete basis built from `admission`.
    ///
    /// # Errors
    /// Returns a typed [`HumanActionAdmissionErrorV1`]; every error commits
    /// no Event.
    pub fn admit_human_action(
        &self,
        port: &mut dyn FactualAdmissionPortV1,
        proposal: &ProposedAction,
        admission: &HumanActionAdmissionV1,
    ) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
        port.lookup_pipeline_receipt(
            admission.observation.timeline_id(),
            admission.idempotency.dedup_key,
            admission.attempt_id,
        )
        .map_err(HumanActionAdmissionErrorV1::Store)
        .and_then(|lookup| match lookup {
            PipelineReceiptLookupV1::Retained(receipt) => Ok(HumanActionReceiptV1 {
                receipt,
                recovered: true,
            }),
            PipelineReceiptLookupV1::Conflict => {
                Err(HumanActionAdmissionErrorV1::IdempotencyConflict)
            }
            PipelineReceiptLookupV1::Absent => self.approve_and_admit(port, proposal, admission),
        })
    }

    fn approve_and_admit(
        &self,
        port: &mut dyn FactualAdmissionPortV1,
        proposal: &ProposedAction,
        admission: &HumanActionAdmissionV1,
    ) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
        let timeline = admission.observation.timeline_id();
        ensure_human_set_headroom(port, timeline)
            .and_then(|()| {
                self.submit_action(timeline, proposal)
                    .map_err(HumanActionAdmissionErrorV1::Submission)
            })
            .and_then(|draft| bound_human_basis(port, admission, proposal, draft))
            .and_then(|basis| {
                port.admit_pipeline_batch(&basis)
                    .map_err(HumanActionAdmissionErrorV1::Store)
            })
            .and_then(settle_human_outcome)
    }
}

/// Refuse the action while the Timeline cannot take one more worst-case Tick
/// (ADR-064 Revision 3, R3.10), before the `ActionApprover` runs.
fn ensure_human_set_headroom(
    port: &dyn FactualAdmissionPortV1,
    timeline: TimelineId,
) -> Result<(), HumanActionAdmissionErrorV1> {
    port.factual_set_counts(timeline)
        .map_err(HumanActionAdmissionErrorV1::Store)
        .and_then(|counts| {
            ensure_factual_set_headroom(counts)
                .map_err(HumanActionAdmissionErrorV1::DependencyDeclaration)
        })
}

/// Keep only an authoritative receipt; every other outcome is typed.
fn settle_human_outcome(
    outcome: PipelineOutcomeV1,
) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
    match outcome {
        PipelineOutcomeV1::Committed(receipt) => Ok(HumanActionReceiptV1 {
            receipt,
            recovered: false,
        }),
        PipelineOutcomeV1::RecoveredDuplicate(receipt) => Ok(HumanActionReceiptV1 {
            receipt,
            recovered: true,
        }),
        rejected => Err(HumanActionAdmissionErrorV1::NotAdmitted(Box::new(rejected))),
    }
}

/// Bind the approved draft and its factual Tick declaration into the basis.
///
/// The declaration is built after the approver ran, from the Tick the prefix
/// is at (ADR-064 R3.8.3).
fn bound_human_basis(
    port: &dyn FactualAdmissionPortV1,
    admission: &HumanActionAdmissionV1,
    proposal: &ProposedAction,
    draft: EventDraft,
) -> Result<PipelineAdmissionBasisV1, HumanActionAdmissionErrorV1> {
    let drafts = vec![draft];
    let evidence = approval_evidence(admission, proposal, &drafts);
    let dependencies = human_dependencies(port, admission, evidence, &drafts)?;
    human_basis(admission, evidence, drafts, dependencies)
        .map_err(HumanActionAdmissionErrorV1::Contract)
}

/// Build the factual Tick declaration of the approved drafts: one
/// human-ingress node per draft and no edge (R3.4.5).
fn human_dependencies(
    port: &dyn FactualPrefixReadPortV1,
    admission: &HumanActionAdmissionV1,
    evidence: Hash,
    drafts: &[EventDraft],
) -> Result<FactualTickDependenciesV1, HumanActionAdmissionErrorV1> {
    let timeline = admission.observation.timeline_id();
    let head = port
        .last_committed_factual_tick(timeline)
        .map_err(HumanActionAdmissionErrorV1::Store)?;
    let context = FactualTickContextV1 {
        timeline_id: timeline,
        tick: head.tick.saturating_add(1),
        attempt_id: admission.attempt_id,
        evidence_digest: evidence,
        authority_grant: admission.authority_grant,
    };
    let shape = FactualTickShapeV1::Human(drafts.to_vec());
    assemble_factual_tick(&context, &shape)
        .map_err(HumanActionAdmissionErrorV1::DependencyDeclaration)
}

/// Build the `HumanProposedAction` basis for one approved draft.
fn human_basis(
    admission: &HumanActionAdmissionV1,
    evidence: Hash,
    drafts: Vec<EventDraft>,
    dependencies: FactualTickDependenciesV1,
) -> Result<PipelineAdmissionBasisV1, PipelineContractErrorV1> {
    PipelineEvidenceRefV1::try_new(evidence)
        .and_then(|approval| {
            PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt_id: Some(admission.attempt_id),
                ingress: Some(PipelineIngressV1::HumanProposedAction),
                observation: Some(admission.observation),
                idempotency: Some(admission.idempotency),
            })
            .map(|attempt| (approval, attempt))
        })
        .and_then(|(approval, attempt)| {
            PipelineDraftBatchV1::try_new(drafts).map(|batch| (approval, attempt, batch))
        })
        .and_then(|(approval, attempt, batch)| {
            PipelineAdmissionBasisV1::try_from_draft(PipelineAdmissionBasisDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt: Some(attempt),
                tentative_result: Some(TentativePipelineResultV1::HumanDomainApproval(approval)),
                precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(
                    admission.observation.observed_through(),
                )),
                security_revisions: Some(admission.security_revisions),
                batch: Some(batch),
                dependencies,
            })
        })
}

/// Bind the domain approval to the attempt, the host authorization that
/// preceded it, the exact proposal, and the exact approved draft.
fn approval_evidence(
    admission: &HumanActionAdmissionV1,
    proposal: &ProposedAction,
    drafts: &[EventDraft],
) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APPROVAL_DOMAIN);
    hasher.update(&admission.attempt_id.as_bytes());
    hasher.update(admission.authorization.digest().as_bytes());
    hasher.update(&proposal.actor_entity_id.inner().to_bytes());
    for field in [
        proposal.event_type.as_str().as_bytes(),
        proposal.capability.as_str().as_bytes(),
        proposal.payload.as_slice(),
    ] {
        hasher.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    hasher.update(pipeline_draft_vector_digest_v1(drafts).as_bytes());
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
