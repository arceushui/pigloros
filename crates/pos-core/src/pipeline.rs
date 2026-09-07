//! Host-owned pipeline contracts for ADR-021.
//!
//! These types keep tentative human approval and AI provider validation distinct
//! while giving both paths one admission basis. They carry no append capability;
//! only committed [`Event`] values can produce a [`PipelineCommitReceiptV1`].

use std::collections::HashSet;

use crate::{AppendIdentity, Event, EventDraft, EventId, Hash, Seq, TimelineId};
use ulid::Ulid;

/// The only pipeline contract version accepted by this implementation.
pub const PIPELINE_CONTRACT_VERSION_V1: u16 = 1;
/// Defensive ceiling for one atomic pipeline batch.
pub const MAX_PIPELINE_DRAFTS_PER_BATCH: usize = 1_024;
/// Defensive ceiling for caller-owned material in one atomic pipeline batch.
pub const MAX_PIPELINE_DRAFT_BATCH_BYTES: usize = 16 * 1024 * 1024;

/// Closed validation failures for ADR-021 pipeline contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PipelineContractErrorV1 {
    #[error("pipeline contract version is unsupported")]
    UnsupportedVersion,
    #[error("pipeline contract is incomplete")]
    Incomplete,
    #[error("pipeline field is outside its public bound")]
    FieldOutOfBounds,
    #[error("pipeline ingress and tentative evidence do not match")]
    IngressMismatch,
    #[error("pipeline draft batch is empty")]
    EmptyBatch,
    #[error("pipeline draft batch exceeds its count bound")]
    BatchCountExceeded,
    #[error("pipeline draft batch exceeds its byte bound")]
    BatchBytesExceeded,
    #[error("pipeline draft is malformed")]
    InvalidDraft,
    #[error("committed Event batch does not match the admitted draft batch")]
    CommittedBatchMismatch,
    #[error("committed Event batch is not in contiguous Timeline Order")]
    NonContiguousCommit,
    #[error("committed Event identities are invalid or duplicated")]
    InvalidCommittedIdentity,
}

/// Opaque identity for one explicit pipeline attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PipelineAttemptIdV1([u8; 16]);

impl PipelineAttemptIdV1 {
    /// Construct a non-zero host-issued attempt identity.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::FieldOutOfBounds`] for an all-zero identity.
    pub fn try_new(bytes: [u8; 16]) -> Result<Self, PipelineContractErrorV1> {
        if bytes == [0; 16] {
            Err(PipelineContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// The two accepted ingress paths retain different trust semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineIngressV1 {
    HumanProposedAction,
    ScheduledAiDriver,
}

/// Exact immutable world cut authorized for one attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineObservationAnchorV1 {
    timeline_id: TimelineId,
    observed_through: Seq,
    snapshot_digest: Hash,
}

impl PipelineObservationAnchorV1 {
    /// Construct a non-empty snapshot anchor.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::FieldOutOfBounds`] for a nil Timeline or zero digest.
    pub fn try_new(
        timeline_id: TimelineId,
        observed_through: Seq,
        snapshot_digest: Hash,
    ) -> Result<Self, PipelineContractErrorV1> {
        if timeline_id.inner() == Ulid::nil() || snapshot_digest == Hash::zero() {
            Err(PipelineContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self {
                timeline_id,
                observed_through,
                snapshot_digest,
            })
        }
    }

    #[must_use]
    pub const fn timeline_id(self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn observed_through(self) -> Seq {
        self.observed_through
    }

    #[must_use]
    pub const fn snapshot_digest(self) -> Hash {
        self.snapshot_digest
    }
}

/// Minimized reference to tentative approval or provider-validation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineEvidenceRefV1(Hash);

impl PipelineEvidenceRefV1 {
    /// Construct a non-zero evidence reference.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::FieldOutOfBounds`] for a zero digest.
    pub fn try_new(digest: Hash) -> Result<Self, PipelineContractErrorV1> {
        if digest == Hash::zero() {
            Err(PipelineContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self(digest))
        }
    }

    #[must_use]
    pub const fn digest(self) -> Hash {
        self.0
    }
}

/// Path-specific tentative result. Neither variant is authoritative.
///
/// Tentative results deliberately do not implement `serde::Serialize` and cannot
/// be converted into a committed receipt:
///
/// ```compile_fail
/// fn assert_serializable<T: serde::Serialize>() {}
/// assert_serializable::<pos_core::TentativePipelineResultV1>();
/// ```
///
/// ```compile_fail
/// fn assert_receipt_source<T: Into<pos_core::PipelineCommitReceiptV1>>() {}
/// assert_receipt_source::<pos_core::TentativePipelineResultV1>();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TentativePipelineResultV1 {
    HumanDomainApproval(PipelineEvidenceRefV1),
    AiProviderValidation(PipelineEvidenceRefV1),
}

impl TentativePipelineResultV1 {
    #[must_use]
    pub const fn ingress(self) -> PipelineIngressV1 {
        match self {
            Self::HumanDomainApproval(_) => PipelineIngressV1::HumanProposedAction,
            Self::AiProviderValidation(_) => PipelineIngressV1::ScheduledAiDriver,
        }
    }

    #[must_use]
    pub const fn evidence(self) -> PipelineEvidenceRefV1 {
        match self {
            Self::HumanDomainApproval(evidence) | Self::AiProviderValidation(evidence) => evidence,
        }
    }
}

/// Path-specific state fence checked at the logical commit serialization point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelinePreconditionV1 {
    ExpectedLogicalHead(Seq),
    DomainStateRevision(Hash),
}

impl PipelinePreconditionV1 {
    /// Construct a non-zero domain-state revision fence.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::FieldOutOfBounds`] for a zero digest.
    pub fn try_domain_state_revision(digest: Hash) -> Result<Self, PipelineContractErrorV1> {
        if digest == Hash::zero() {
            Err(PipelineContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self::DomainStateRevision(digest))
        }
    }
}

/// Unvalidated security revisions that must be rechecked together at commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineSecurityRevisionsDraftV1 {
    pub authority: Hash,
    pub consent: Hash,
    pub capability: Hash,
    pub delegation: Hash,
    pub policy: Hash,
    pub execution_profile: Hash,
    pub erasure: Hash,
}

/// Exact security revision set bound by one admission basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineSecurityRevisionsV1(PipelineSecurityRevisionsDraftV1);

impl PipelineSecurityRevisionsV1 {
    /// Validate that every required security revision is present.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::Incomplete`] when any revision is zero.
    pub fn try_from_draft(
        draft: PipelineSecurityRevisionsDraftV1,
    ) -> Result<Self, PipelineContractErrorV1> {
        if draft.authority == Hash::zero()
            || draft.consent == Hash::zero()
            || draft.capability == Hash::zero()
            || draft.delegation == Hash::zero()
            || draft.policy == Hash::zero()
            || draft.execution_profile == Hash::zero()
            || draft.erasure == Hash::zero()
        {
            Err(PipelineContractErrorV1::Incomplete)
        } else {
            Ok(Self(draft))
        }
    }

    #[must_use]
    pub const fn as_draft(&self) -> PipelineSecurityRevisionsDraftV1 {
        self.0
    }
}

/// One bounded, ordered, tentative Event-draft batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineDraftBatchV1 {
    drafts: Vec<EventDraft>,
    content_bytes: usize,
    digest: Hash,
}

impl PipelineDraftBatchV1 {
    /// Validate and bind a tentative draft batch without assigning Event identity or order.
    ///
    /// # Errors
    /// Returns a closed error for an empty, malformed, or oversized batch.
    pub fn try_new(drafts: Vec<EventDraft>) -> Result<Self, PipelineContractErrorV1> {
        if drafts.is_empty() {
            return Err(PipelineContractErrorV1::EmptyBatch);
        }
        if drafts.len() > MAX_PIPELINE_DRAFTS_PER_BATCH {
            return Err(PipelineContractErrorV1::BatchCountExceeded);
        }
        if drafts.iter().any(invalid_draft) {
            return Err(PipelineContractErrorV1::InvalidDraft);
        }
        let content_bytes = drafts
            .iter()
            .try_fold(0usize, |total, draft| {
                let next = total.saturating_add(draft_content_bytes(draft));
                (next <= MAX_PIPELINE_DRAFT_BATCH_BYTES).then_some(next)
            })
            .ok_or(PipelineContractErrorV1::BatchBytesExceeded)?;
        let digest = digest_drafts(&drafts);
        Ok(Self {
            drafts,
            content_bytes,
            digest,
        })
    }

    #[must_use]
    pub fn drafts(&self) -> &[EventDraft] {
        &self.drafts
    }

    #[must_use]
    pub const fn content_bytes(&self) -> usize {
        self.content_bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Hash {
        self.digest
    }
}

/// Unvalidated fields for one explicit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineAttemptDraftV1 {
    pub contract_version: u16,
    pub attempt_id: Option<PipelineAttemptIdV1>,
    pub ingress: Option<PipelineIngressV1>,
    pub observation: Option<PipelineObservationAnchorV1>,
    pub idempotency: Option<AppendIdentity>,
}

/// One explicit, retry-distinct attempt rooted at an authorized observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineAttemptV1 {
    attempt_id: PipelineAttemptIdV1,
    ingress: PipelineIngressV1,
    observation: PipelineObservationAnchorV1,
    idempotency: AppendIdentity,
}

impl PipelineAttemptV1 {
    /// Validate a complete V1 attempt.
    ///
    /// # Errors
    /// Returns a closed error for an unsupported version, missing field, or zero idempotency value.
    pub fn try_from_draft(draft: PipelineAttemptDraftV1) -> Result<Self, PipelineContractErrorV1> {
        if draft.contract_version != PIPELINE_CONTRACT_VERSION_V1 {
            return Err(PipelineContractErrorV1::UnsupportedVersion);
        }
        let (Some(attempt_id), Some(ingress), Some(observation), Some(idempotency)) = (
            draft.attempt_id,
            draft.ingress,
            draft.observation,
            draft.idempotency,
        ) else {
            return Err(PipelineContractErrorV1::Incomplete);
        };
        if idempotency.dedup_key.as_bytes() == [0; 32] || idempotency.scope.as_bytes() == [0; 32] {
            return Err(PipelineContractErrorV1::FieldOutOfBounds);
        }
        Ok(Self {
            attempt_id,
            ingress,
            observation,
            idempotency,
        })
    }

    #[must_use]
    pub const fn attempt_id(self) -> PipelineAttemptIdV1 {
        self.attempt_id
    }

    #[must_use]
    pub const fn ingress(self) -> PipelineIngressV1 {
        self.ingress
    }

    #[must_use]
    pub const fn observation(self) -> PipelineObservationAnchorV1 {
        self.observation
    }

    #[must_use]
    pub const fn idempotency(self) -> AppendIdentity {
        self.idempotency
    }
}

/// Unvalidated fields for the common host-admission contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineAdmissionBasisDraftV1 {
    pub contract_version: u16,
    pub attempt: Option<PipelineAttemptV1>,
    pub tentative_result: Option<TentativePipelineResultV1>,
    pub precondition: Option<PipelinePreconditionV1>,
    pub security_revisions: Option<PipelineSecurityRevisionsV1>,
    pub batch: Option<PipelineDraftBatchV1>,
}

/// Complete evidence and state basis that must be revalidated atomically with commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineAdmissionBasisV1 {
    attempt: PipelineAttemptV1,
    tentative_result: TentativePipelineResultV1,
    precondition: PipelinePreconditionV1,
    security_revisions: PipelineSecurityRevisionsV1,
    batch: PipelineDraftBatchV1,
}

impl PipelineAdmissionBasisV1 {
    /// Validate one common admission basis while retaining its human or AI trust path.
    ///
    /// # Errors
    /// Returns a closed error for an unsupported version, incomplete basis, or path mismatch.
    pub fn try_from_draft(
        draft: PipelineAdmissionBasisDraftV1,
    ) -> Result<Self, PipelineContractErrorV1> {
        if draft.contract_version != PIPELINE_CONTRACT_VERSION_V1 {
            return Err(PipelineContractErrorV1::UnsupportedVersion);
        }
        let (
            Some(attempt),
            Some(tentative_result),
            Some(precondition),
            Some(security_revisions),
            Some(batch),
        ) = (
            draft.attempt,
            draft.tentative_result,
            draft.precondition,
            draft.security_revisions,
            draft.batch,
        )
        else {
            return Err(PipelineContractErrorV1::Incomplete);
        };
        if attempt.ingress() != tentative_result.ingress() {
            return Err(PipelineContractErrorV1::IngressMismatch);
        }
        Ok(Self {
            attempt,
            tentative_result,
            precondition,
            security_revisions,
            batch,
        })
    }

    #[must_use]
    pub const fn attempt(&self) -> &PipelineAttemptV1 {
        &self.attempt
    }

    #[must_use]
    pub const fn tentative_result(&self) -> TentativePipelineResultV1 {
        self.tentative_result
    }

    #[must_use]
    pub const fn precondition(&self) -> PipelinePreconditionV1 {
        self.precondition
    }

    #[must_use]
    pub const fn security_revisions(&self) -> PipelineSecurityRevisionsV1 {
        self.security_revisions
    }

    #[must_use]
    pub const fn batch(&self) -> &PipelineDraftBatchV1 {
        &self.batch
    }
}

/// Store-assigned identity and Timeline Order for one committed Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedPipelineEventV1 {
    event_id: EventId,
    seq: Seq,
}

impl CommittedPipelineEventV1 {
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }

    #[must_use]
    pub const fn seq(self) -> Seq {
        self.seq
    }
}

/// Authoritative receipt derived only from a committed Event batch.
///
/// The receipt deliberately has no general serialization contract; exact public
/// route fields remain owned by the Gateway contract:
///
/// ```compile_fail
/// fn assert_serializable<T: serde::Serialize>() {}
/// assert_serializable::<pos_core::PipelineCommitReceiptV1>();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineCommitReceiptV1 {
    attempt_id: PipelineAttemptIdV1,
    timeline_id: TimelineId,
    draft_batch_digest: Hash,
    committed_events: Vec<CommittedPipelineEventV1>,
}

impl PipelineCommitReceiptV1 {
    /// Bind a validated admission basis to the exact committed Events returned by the store.
    ///
    /// # Errors
    /// Returns a closed error when identity, content, count, or Timeline Order is invalid.
    pub fn try_from_committed_events(
        basis: &PipelineAdmissionBasisV1,
        events: &[Event],
    ) -> Result<Self, PipelineContractErrorV1> {
        if events.len() != basis.batch.drafts.len() || digest_events(events) != basis.batch.digest {
            return Err(PipelineContractErrorV1::CommittedBatchMismatch);
        }
        if events.windows(2).any(|pair| {
            pair[0]
                .seq
                .as_u64()
                .checked_add(1)
                .is_none_or(|next| next != pair[1].seq.as_u64())
        }) {
            return Err(PipelineContractErrorV1::NonContiguousCommit);
        }
        let mut identities = HashSet::with_capacity(events.len());
        if events
            .iter()
            .any(|event| event.id.inner() == Ulid::nil() || !identities.insert(event.id))
        {
            return Err(PipelineContractErrorV1::InvalidCommittedIdentity);
        }
        Ok(Self {
            attempt_id: basis.attempt.attempt_id,
            timeline_id: basis.attempt.observation.timeline_id,
            draft_batch_digest: basis.batch.digest,
            committed_events: events
                .iter()
                .map(|event| CommittedPipelineEventV1 {
                    event_id: event.id,
                    seq: event.seq,
                })
                .collect(),
        })
    }

    #[must_use]
    pub const fn attempt_id(&self) -> PipelineAttemptIdV1 {
        self.attempt_id
    }

    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    #[must_use]
    pub const fn draft_batch_digest(&self) -> Hash {
        self.draft_batch_digest
    }

    #[must_use]
    pub fn committed_events(&self) -> &[CommittedPipelineEventV1] {
        &self.committed_events
    }
}

/// Closed host outcome for one pipeline attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipelineOutcomeV1 {
    Rejected,
    InvalidObservation,
    AuthorityRevoked,
    AuthorityExpired,
    PolicyIndeterminate,
    ResourceExhausted,
    InvalidPluginResult,
    InvalidProviderResult,
    DomainConflict,
    AdmissionConflict,
    Committed(PipelineCommitReceiptV1),
    RecoveredDuplicate(PipelineCommitReceiptV1),
}

fn invalid_draft(draft: &EventDraft) -> bool {
    draft.entity.inner() == Ulid::nil() || draft.event_type.as_str().is_empty()
}

fn draft_content_bytes(draft: &EventDraft) -> usize {
    16usize
        .saturating_add(draft.event_type.as_str().len())
        .saturating_add(draft.payload.len())
        .saturating_add(16)
        .saturating_add(16)
        .saturating_add(4)
}

fn digest_drafts(drafts: &[EventDraft]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.PipelineDraftBatch.v1\0");
    hasher.update(&usize_bytes(drafts.len()));
    for draft in drafts {
        digest_intent(
            &mut hasher,
            draft.entity.inner().to_bytes(),
            draft.event_type.as_str(),
            draft.payload.as_slice(),
            draft.causation_id,
            draft.correlation_id,
            draft.schema_version.as_u32(),
        );
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_events(events: &[Event]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.PipelineDraftBatch.v1\0");
    hasher.update(&usize_bytes(events.len()));
    for event in events {
        digest_intent(
            &mut hasher,
            event.entity.inner().to_bytes(),
            event.event_type.as_str(),
            event.payload.as_slice(),
            event.causation_id,
            event.correlation_id,
            event.schema_version.as_u32(),
        );
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn digest_intent(
    hasher: &mut blake3::Hasher,
    entity: [u8; 16],
    event_type: &str,
    payload: &[u8],
    causation_id: Option<EventId>,
    correlation_id: Option<crate::CorrelationId>,
    schema_version: u32,
) {
    hasher.update(&entity);
    digest_bytes(hasher, event_type.as_bytes());
    digest_bytes(hasher, payload);
    digest_optional_ulid(hasher, causation_id.map(|id| id.inner().to_bytes()));
    digest_optional_ulid(hasher, correlation_id.map(|id| id.inner().to_bytes()));
    hasher.update(&schema_version.to_be_bytes());
}

fn digest_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&usize_bytes(value.len()));
    hasher.update(value);
}

fn digest_optional_ulid(hasher: &mut blake3::Hasher, value: Option<[u8; 16]>) {
    match value {
        Some(bytes) => {
            hasher.update(&[1]);
            hasher.update(&bytes);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn usize_bytes(value: usize) -> [u8; 8] {
    u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes()
}
