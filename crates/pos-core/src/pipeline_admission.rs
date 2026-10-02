//! Host-only ADR-021 admitted-batch store port.
//!
//! The trusted host publishes one [`PipelineAdmissionFenceV1`] per Timeline
//! through [`PipelineAdmissionFencePublisherV1`]. An adapter compares a
//! complete [`PipelineAdmissionBasisV1`] against that persisted fence, the
//! persisted authority chain, the persisted erasure inventory generation, the
//! Logical Head, and the retained idempotency receipts inside one logical
//! serialization point, then commits the whole ordered Event batch or nothing.
//!
//! # Persisted revision sources
//!
//! Each of the seven security revisions is compared with the exact persisted
//! state owned by its accepted contract where the Event Store owns one:
//!
//! - **authority**: [`pipeline_authority_revision_v1`] over the persisted
//!   root-to-leaf grant chain (#178) named by the fence, at its current
//!   revocation epoch. It binds every grant identity, delegation link, and
//!   per-grant policy revision of that chain.
//! - **delegation**: [`pipeline_delegation_revision_v1`] over the same
//!   persisted chain: its delegation edges and every persisted revocation
//!   record on its authority Timeline (#483), so a revocation another host
//!   persists in the same store stales every basis published before it.
//! - **erasure**: [`pipeline_erasure_revision_v1`] over the persisted erasure
//!   inventory generation (#186) that the adapter has already validated
//!   against its bound containment gate.
//! - **consent, capability, policy, execution profile**: the
//!   Event Store owns no separate persisted revision for these yet. The
//!   host-published fence, persisted in the same store and replaced only by the
//!   trusted host, is their persisted source until an owning contract stores
//!   them in the Event Store transaction. The EPF1 execution profile is
//!   persisted by the Gateway trust-policy registry (#323, #446) outside the
//!   Event Store transaction, so the host publishes its revision here.

use std::num::NonZeroUsize;

use crate::{
    pipeline::PIPELINE_SECURITY_REVISION_COUNT_V1,
    store::{AppendDedupKey, PurgeOutcome},
    CoreError, ErasureReferenceV1, Hash, PersistedAuthorityV1, PipelineAdmissionBasisV1,
    PipelineAttemptIdV1, PipelineCommitReceiptV1, PipelineContractErrorV1, PipelineOutcomeV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, TimelineId,
};

const FENCE_VERSION_V1: u8 = 1;
const HASH_BYTES: usize = 32;
const REVISIONS_OFFSET: usize = 1 + HASH_BYTES;
const DOMAIN_FLAG_OFFSET: usize =
    REVISIONS_OFFSET + HASH_BYTES * PIPELINE_SECURITY_REVISION_COUNT_V1;
const DOMAIN_OFFSET: usize = DOMAIN_FLAG_OFFSET + 1;
const BUDGET_OFFSET: usize = DOMAIN_OFFSET + HASH_BYTES;

/// Exact byte length of one persisted V1 admission fence.
pub const PIPELINE_ADMISSION_FENCE_BYTES_V1: usize = BUDGET_OFFSET + 8;

/// Current host-published admission state for one Timeline.
///
/// The fence names the persisted authority leaf grant whose delegation chain
/// the adapter resolves at commit, the exact security revisions an admission
/// basis must match, the optional current domain-state revision, and the
/// remaining Event budget consumed atomically by each committed batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PipelineAdmissionFenceV1 {
    authority_grant: Hash,
    security_revisions: PipelineSecurityRevisionsV1,
    domain_state_revision: Option<Hash>,
    remaining_event_budget: u64,
}

impl PipelineAdmissionFenceV1 {
    /// Construct a complete admission fence.
    ///
    /// # Errors
    /// Returns [`PipelineContractErrorV1::FieldOutOfBounds`] for a zero
    /// authority grant or zero domain-state revision.
    pub fn try_new(
        authority_grant: Hash,
        security_revisions: PipelineSecurityRevisionsV1,
        domain_state_revision: Option<Hash>,
        remaining_event_budget: u64,
    ) -> Result<Self, PipelineContractErrorV1> {
        if authority_grant == Hash::zero() || domain_state_revision == Some(Hash::zero()) {
            Err(PipelineContractErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self {
                authority_grant,
                security_revisions,
                domain_state_revision,
                remaining_event_budget,
            })
        }
    }

    #[must_use]
    pub const fn authority_grant(&self) -> Hash {
        self.authority_grant
    }

    #[must_use]
    pub const fn security_revisions(&self) -> PipelineSecurityRevisionsV1 {
        self.security_revisions
    }

    #[must_use]
    pub const fn domain_state_revision(&self) -> Option<Hash> {
        self.domain_state_revision
    }

    #[must_use]
    pub const fn remaining_event_budget(&self) -> u64 {
        self.remaining_event_budget
    }

    /// Return this fence after one committed batch consumed `events` of its budget.
    ///
    /// Returns `None` when the batch exceeds the remaining budget.
    #[must_use]
    pub fn after_commit(&self, events: u64) -> Option<Self> {
        self.remaining_event_budget
            .checked_sub(events)
            .map(|remaining_event_budget| Self {
                remaining_event_budget,
                ..*self
            })
    }

    /// Encode the exact fixed-width V1 persistence record.
    #[must_use]
    pub fn to_persistence_bytes(&self) -> [u8; PIPELINE_ADMISSION_FENCE_BYTES_V1] {
        let mut bytes = [0_u8; PIPELINE_ADMISSION_FENCE_BYTES_V1];
        bytes[0] = FENCE_VERSION_V1;
        for (index, value) in std::iter::once(self.authority_grant)
            .chain(self.security_revisions.as_draft().ordered())
            .enumerate()
        {
            let offset = 1 + index * HASH_BYTES;
            bytes[offset..offset + HASH_BYTES].copy_from_slice(value.as_bytes());
        }
        if let Some(domain) = self.domain_state_revision {
            bytes[DOMAIN_FLAG_OFFSET] = 1;
            bytes[DOMAIN_OFFSET..BUDGET_OFFSET].copy_from_slice(domain.as_bytes());
        }
        bytes[BUDGET_OFFSET..].copy_from_slice(&self.remaining_event_budget.to_be_bytes());
        bytes
    }

    /// Decode and validate one exact fixed-width V1 persistence record.
    ///
    /// # Errors
    /// Returns a closed contract error for a wrong length, unsupported version,
    /// noncanonical domain field, or incomplete security revision set.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, PipelineContractErrorV1> {
        let Ok(fixed) = <&[u8; PIPELINE_ADMISSION_FENCE_BYTES_V1]>::try_from(bytes) else {
            return Err(PipelineContractErrorV1::FieldOutOfBounds);
        };
        if fixed[0] != FENCE_VERSION_V1 {
            return Err(PipelineContractErrorV1::UnsupportedVersion);
        }
        let domain = hash_at(fixed, DOMAIN_OFFSET);
        let domain_state_revision = match fixed[DOMAIN_FLAG_OFFSET] {
            0 if domain == Hash::zero() => None,
            1 => Some(domain),
            _ => return Err(PipelineContractErrorV1::FieldOutOfBounds),
        };
        let mut budget = [0_u8; 8];
        budget.copy_from_slice(&fixed[BUDGET_OFFSET..]);
        PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1::from_ordered(
            std::array::from_fn(|index| hash_at(fixed, REVISIONS_OFFSET + index * HASH_BYTES)),
        ))
        .and_then(|security_revisions| {
            Self::try_new(
                hash_at(fixed, 1),
                security_revisions,
                domain_state_revision,
                u64::from_be_bytes(budget),
            )
        })
    }
}

/// Derive the authority revision an admission basis must bind for one
/// persisted root-to-leaf delegation chain at its current revocation epoch.
#[must_use]
pub fn pipeline_authority_revision_v1(authority: &PersistedAuthorityV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.PipelineAuthorityRevision.v1\0");
    hasher.update(&authority.revocation_epoch().to_be_bytes());
    for grant in authority.chain().grants() {
        hasher.update(grant.grant_id().as_bytes());
        hasher.update(grant.policy_revision().as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Derive the delegation revision an admission basis must bind for one
/// persisted root-to-leaf delegation chain.
///
/// It binds the current revocation epoch, every delegation edge of the chain
/// (each grant in root-to-leaf order with its delegation depth and bound), and
/// every field of every persisted revocation record on the chain's authority
/// Timeline. Any persisted revocation change therefore moves it, even between
/// two revocation states with the same epoch.
#[must_use]
pub fn pipeline_delegation_revision_v1(authority: &PersistedAuthorityV1) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.PipelineDelegationRevision.v1\0");
    hasher.update(&authority.revocation_epoch().to_be_bytes());
    for grant in authority.chain().grants() {
        hasher.update(b"E");
        hasher.update(grant.grant_id().as_bytes());
        hasher.update(&[grant.delegation_depth(), grant.max_delegation_depth()]);
    }
    for revocation in authority.revocations() {
        hasher.update(b"R");
        hasher.update(revocation.grant_id().as_bytes());
        hasher.update(&revocation.authority_timeline().inner().to_bytes());
        hasher.update(&revocation.fence_position().as_u64().to_be_bytes());
        hasher.update(&revocation.revocation_epoch().to_be_bytes());
        hasher.update(revocation.policy_revision().as_bytes());
        hasher.update(revocation.authority_registry_digest().as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Derive the erasure revision an admission basis must bind for the
/// persisted erasure inventory generation.
///
/// `None` is the state before any complete inventory is installed; adapters
/// reach it only with the unverified test-fixture gate, because a production
/// gate without an installed inventory fails closed before comparison.
#[must_use]
pub fn pipeline_erasure_revision_v1(inventory_generation: Option<ErasureReferenceV1>) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.PipelineErasureRevision.v1\0");
    let (presence, digest) =
        inventory_generation.map_or((0_u8, [0_u8; 32]), |generation| (1, generation.digest()));
    hasher.update(&[presence]);
    hasher.update(&digest);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Retained admitted-batch state for one idempotency key, read without an
/// admission basis.
///
/// The retained receipt is the only recovery result: a lookup never
/// reruns approval or provider validation and never commits an Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PipelineReceiptLookupV1 {
    /// No unexpired receipt is retained for the idempotency key.
    Absent,
    /// The named attempt committed on the named Timeline; its original receipt.
    Retained(PipelineCommitReceiptV1),
    /// Another attempt or Timeline holds the idempotency key.
    Conflict,
}

/// Host-only capability that publishes the admission fence for one Timeline.
///
/// Publishing is deliberately separate from [`PipelineAdmissionPortV1`]: the
/// trusted host derives a fence from its own authority, policy, and budget
/// state, while the admission port only consumes it. Neither capability may
/// be exposed to Plugin, provider, Driver, or `ActionApprover` code.
pub trait PipelineAdmissionFencePublisherV1 {
    /// Install or replace the host-published admission fence for one Timeline.
    ///
    /// The write is serialized with admissions under the Timeline's erasure
    /// fence, so a frozen erasure scope rejects it and leaves the fence
    /// unchanged.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] for an unknown or invisible
    /// Timeline, an erasure error for a frozen or unavailable erasure scope,
    /// or a storage error when the fence cannot be persisted.
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError>;

    /// Read the current persisted admission fence for one Timeline.
    ///
    /// # Errors
    /// Returns a storage error when a persisted fence cannot be read or validated.
    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError>;
}

/// Host-only store port that atomically compares an admission basis and
/// commits its bounded ordered Event batch.
///
/// This capability is deliberately separate from [`crate::EventStore`]: the
/// trusted host composition root owns it and must never expose it to Plugin,
/// provider, Driver, or `ActionApprover` code.
///
/// # Serialization point
///
/// Every comparison and the commit run inside one adapter serialization
/// point: exclusive `&mut self` access under the Timeline's erasure fence, and
/// for `SQLite` additionally one `BEGIN IMMEDIATE` transaction. Concurrent
/// same-Timeline attempts therefore observe the authoritative Logical Head
/// (including Fork history) one at a time; at most one attempt can commit
/// against a given head. A second `SQLite` connection that writes the same
/// database invalidates this connection's validated erasure inventory, so a
/// cross-connection race fails closed rather than committing twice.
pub trait PipelineAdmissionPortV1 {
    /// Atomically compare `basis` and commit its complete Event batch.
    ///
    /// The basis Timeline is the observation anchor's Timeline. A retained
    /// exact retry returns [`PipelineOutcomeV1::RecoveredDuplicate`] with the
    /// original receipt before any other comparison; a different basis under
    /// the same idempotency key returns [`PipelineOutcomeV1::AdmissionConflict`].
    /// Every other non-`Committed` outcome commits no Event and no receipt.
    ///
    /// # Errors
    /// Returns an erasure, visibility, clock, or storage error. Every error
    /// and every non-`Committed` outcome leaves the Timeline, fence, and
    /// retained receipts unchanged unless it is
    /// [`CoreError::StorageOutcomeUnknown`]. An expired receipt for the same
    /// idempotency key is replaced only by a successful commit.
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError>;

    /// Look up the retained receipt for one idempotency key before a new
    /// attempt runs approval.
    ///
    /// Returns [`PipelineReceiptLookupV1::Retained`] with the original
    /// receipt only when `attempt_id` committed under `key` on `timeline`,
    /// and [`PipelineReceiptLookupV1::Conflict`] when another attempt or
    /// Timeline holds the key. An expired receipt is
    /// [`PipelineReceiptLookupV1::Absent`], as it is for
    /// [`Self::admit_pipeline_batch`]. The lookup runs under the Timeline's
    /// erasure fence and never changes the Timeline, fence, or receipts.
    ///
    /// # Errors
    /// Returns an erasure, visibility, clock, or storage error.
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError>;

    /// Remove at most `limit` admission receipts whose retention horizon has
    /// passed on the store-owned clock.
    ///
    /// # Errors
    /// Returns a clock or storage error when cleanup cannot complete.
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError>;
}

fn hash_at(bytes: &[u8; PIPELINE_ADMISSION_FENCE_BYTES_V1], offset: usize) -> Hash {
    let mut value = [0_u8; HASH_BYTES];
    value.copy_from_slice(&bytes[offset..offset + HASH_BYTES]);
    Hash::from_bytes(value)
}
