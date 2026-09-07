//! Host-owned artifact registration and replay-claim evaluation.

use super::{
    ErasureArtifactClassV1, ErasureErrorV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1,
};

/// Data classification fixed before an artifact is committed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactDataClassV1 {
    /// Subject-controlled encrypted bytes.
    PrivateSubjectData,
    /// Data retained for a recorded audience, purpose, and withdrawal policy.
    ConsentedSharedData,
    /// Explicitly published material governed by its publication policy.
    PublicRecord,
    /// A policy-admitted non-identifying aggregate.
    AggregateData,
    /// Minimized identities, ordering, and commitments without subject payload.
    StructuralAuditMetadata,
}

/// Whether an artifact is required to support its enclosing claim.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactOptionalityV1 {
    /// Absence weakens the enclosing artifact to unverifiable.
    Required,
    /// Absence does not weaken the enclosing artifact.
    Optional,
}

/// Transition fixed for an artifact before erasure begins.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactTransitionRuleV1 {
    /// The artifact contains no erased material and remains exact.
    PreserveExact,
    /// Protected viewer fields disappear while authoritative evidence survives.
    RedactViews,
    /// Only minimized structural identity and ordering survive.
    RetainStructure,
    /// Required bytes or keys are destroyed.
    Remove,
}

impl ArtifactTransitionRuleV1 {
    const fn claim(self) -> ErasureReplayClaimV1 {
        match self {
            Self::PreserveExact => ErasureReplayClaimV1::Exact,
            Self::RedactViews => ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            Self::RetainStructure => ErasureReplayClaimV1::StructuralOnly,
            Self::Remove => ErasureReplayClaimV1::UnverifiableArtifactsMissing,
        }
    }
}

/// Current owner-reported state of one registered artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactStateV1 {
    /// Original bytes and every required key remain available.
    Retained,
    /// The registered transition rule was applied successfully.
    TransitionApplied,
    /// Required bytes, schema, key, parent cut, runtime, or output are absent.
    Missing,
    /// Immutable bytes remain for audit but their generation is quarantined.
    Invalidated,
}

/// Immutable policy facts registered by the adapter that owns artifact bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegisteredArtifactV1 {
    /// Closed artifact class used by ADR-060 receipts.
    pub artifact_class: ErasureArtifactClassV1,
    /// Content identity of the registered artifact.
    pub artifact_digest: ErasureReferenceV1,
    /// Data class fixed before commit.
    pub data_class: ArtifactDataClassV1,
    /// Key role, when artifact availability depends on a role-separated key.
    pub key_role: Option<ErasureKeyRoleV1>,
    /// Registered adapter/owner identity.
    pub owner: ErasureReferenceV1,
    /// Whether the artifact is required by its enclosing claim.
    pub optionality: ArtifactOptionalityV1,
    /// One-way transition applied after a successful erasure acknowledgement.
    pub transition_rule: ArtifactTransitionRuleV1,
}

/// One artifact and its current claim/state supplied to the evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactClaimInputV1 {
    /// Immutable registration facts.
    pub registration: RegisteredArtifactV1,
    /// Claim supported before applying the current state.
    pub current_claim: ErasureReplayClaimV1,
    /// Current owner-reported artifact state.
    pub state: ArtifactStateV1,
}

/// Deterministic result for one registered artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluatedArtifactClaimV1 {
    /// Registered artifact identity.
    pub artifact_digest: ErasureReferenceV1,
    /// Claim before evaluation.
    pub from: ErasureReplayClaimV1,
    /// Claim after evaluation.
    pub to: ErasureReplayClaimV1,
    /// Whether this exact state may be used as authoritative runtime input.
    pub authoritative_use_permitted: bool,
}

/// Aggregate result plus canonically ordered per-artifact transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayClaimEvaluationV1 {
    /// Weakest claim among required members and the enclosing claim.
    pub replay_claim: ErasureReplayClaimV1,
    /// Per-artifact results in canonical `(class, digest)` order.
    pub artifacts: Vec<EvaluatedArtifactClaimV1>,
}

/// Sole host-owned policy evaluator for ADR-060 artifact claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayClaimEvaluatorV1;

impl ReplayClaimEvaluatorV1 {
    /// Evaluate registered artifacts without permitting claim strengthening.
    ///
    /// Optional members still receive a per-artifact result but do not weaken
    /// the enclosing export or manifest claim. Duplicate registrations fail
    /// closed rather than allowing arrival order to select policy.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::PolicyConflict`] for duplicate artifact
    /// identities.
    pub fn evaluate(
        enclosing_claim: ErasureReplayClaimV1,
        inputs: &[ArtifactClaimInputV1],
    ) -> Result<ReplayClaimEvaluationV1, ErasureErrorV1> {
        let mut inputs = inputs.to_vec();
        inputs.sort_unstable_by_key(|input| {
            (
                input.registration.artifact_class,
                input.registration.artifact_digest,
            )
        });
        if inputs.windows(2).any(|pair| {
            pair[0].registration.artifact_class == pair[1].registration.artifact_class
                && pair[0].registration.artifact_digest == pair[1].registration.artifact_digest
        }) {
            return Err(ErasureErrorV1::PolicyConflict);
        }

        let mut replay_claim = enclosing_claim;
        let artifacts = inputs
            .into_iter()
            .map(|input| {
                let disposition_claim = match input.state {
                    ArtifactStateV1::Retained => input.current_claim,
                    ArtifactStateV1::TransitionApplied => input.registration.transition_rule.claim(),
                    ArtifactStateV1::Missing | ArtifactStateV1::Invalidated => {
                        ErasureReplayClaimV1::UnverifiableArtifactsMissing
                    }
                };
                let to = weaker(input.current_claim, disposition_claim);
                if input.registration.optionality == ArtifactOptionalityV1::Required {
                    replay_claim = weaker(replay_claim, to);
                }
                EvaluatedArtifactClaimV1 {
                    artifact_digest: input.registration.artifact_digest,
                    from: input.current_claim,
                    to,
                    authoritative_use_permitted: matches!(
                        input.state,
                        ArtifactStateV1::Retained | ArtifactStateV1::TransitionApplied
                    ) && matches!(
                        to,
                        ErasureReplayClaimV1::Exact
                            | ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
                    ),
                }
            })
            .collect();
        Ok(ReplayClaimEvaluationV1 {
            replay_claim,
            artifacts,
        })
    }
}

const fn weaker(
    current: ErasureReplayClaimV1,
    candidate: ErasureReplayClaimV1,
) -> ErasureReplayClaimV1 {
    if current.preserves_or_weakens(candidate) {
        candidate
    } else {
        current
    }
}
