//! Host-only ADR-021 admitted-batch store port.
//!
//! The trusted host publishes one [`PipelineAdmissionFenceV1`] per Timeline.
//! An adapter compares a complete [`PipelineAdmissionBasisV1`] against that
//! fence, the persisted authority chain, the erasure fence, the Logical Head,
//! and the retained idempotency receipts inside one logical serialization
//! point, then commits the whole ordered Event batch or nothing.

use std::num::NonZeroUsize;

use crate::{
    store::PurgeOutcome, CoreError, Hash, PersistedAuthorityV1, PipelineAdmissionBasisV1,
    PipelineContractErrorV1, PipelineOutcomeV1, PipelineSecurityRevisionsDraftV1,
    PipelineSecurityRevisionsV1, TimelineId,
};

const FENCE_VERSION_V1: u8 = 1;
const HASH_BYTES: usize = 32;
const REVISION_COUNT: usize = 7;
const DOMAIN_FLAG_OFFSET: usize = 1 + HASH_BYTES * (1 + REVISION_COUNT);
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
            .chain(revision_values(self.security_revisions.as_draft()))
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
        PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
            authority: hash_at(fixed, 1 + HASH_BYTES),
            consent: hash_at(fixed, 1 + 2 * HASH_BYTES),
            capability: hash_at(fixed, 1 + 3 * HASH_BYTES),
            delegation: hash_at(fixed, 1 + 4 * HASH_BYTES),
            policy: hash_at(fixed, 1 + 5 * HASH_BYTES),
            execution_profile: hash_at(fixed, 1 + 6 * HASH_BYTES),
            erasure: hash_at(fixed, 1 + 7 * HASH_BYTES),
        })
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

/// Host-only store port that atomically compares an admission basis and
/// commits its bounded ordered Event batch.
///
/// This capability is deliberately separate from [`crate::EventStore`]: the
/// trusted host composition root owns it and must never expose it to Plugin,
/// provider, Driver, or `ActionApprover` code.
pub trait PipelineAdmissionPortV1 {
    /// Install or replace the host-published admission fence for one Timeline.
    ///
    /// # Errors
    /// Returns [`CoreError::TimelineNotFound`] for an unknown or invisible
    /// Timeline, or a storage error when the fence cannot be persisted.
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
    /// leaves the Timeline, fence, and retained receipts unchanged unless it is
    /// [`CoreError::StorageOutcomeUnknown`].
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError>;

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

const fn revision_values(revisions: PipelineSecurityRevisionsDraftV1) -> [Hash; REVISION_COUNT] {
    [
        revisions.authority,
        revisions.consent,
        revisions.capability,
        revisions.delegation,
        revisions.policy,
        revisions.execution_profile,
        revisions.erasure,
    ]
}

fn hash_at(bytes: &[u8; PIPELINE_ADMISSION_FENCE_BYTES_V1], offset: usize) -> Hash {
    let mut value = [0_u8; HASH_BYTES];
    value.copy_from_slice(&bytes[offset..offset + HASH_BYTES]);
    Hash::from_bytes(value)
}
