//! Host-owned artifact registration and replay-claim evaluation.

use super::{
    ErasureArtifactClassV1, ErasureErrorV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ERASURE_MAX_TARGETS,
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
    const fn disposition(self) -> (ErasureReplayClaimV1, ArtifactRedactionStateV1) {
        match self {
            Self::PreserveExact => (ErasureReplayClaimV1::Exact, ArtifactRedactionStateV1::None),
            Self::RedactViews => (
                ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
                ArtifactRedactionStateV1::RedactedViews,
            ),
            Self::RetainStructure => (
                ErasureReplayClaimV1::StructuralOnly,
                ArtifactRedactionStateV1::StructuralOnly,
            ),
            Self::Remove => (
                ErasureReplayClaimV1::UnverifiableArtifactsMissing,
                ArtifactRedactionStateV1::EvidenceMissing,
            ),
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
    /// The parent Timeline cut is unavailable.
    MissingParentCut,
    /// A frozen exogenous input is unavailable.
    MissingFrozenInput,
    /// A required role-separated key is unavailable.
    MissingKey,
    /// A required schema or upcaster is unavailable.
    MissingSchema,
    /// A required Plugin artifact is unavailable.
    MissingPlugin,
    /// A required model artifact is unavailable.
    MissingModel,
    /// A required runtime artifact is unavailable.
    MissingRuntime,
    /// A required authoritative output is unavailable.
    MissingRequiredOutput,
    /// The registered artifact was erased rather than structurally retained.
    Erased,
    /// Immutable bytes remain for audit but their generation is quarantined.
    Invalidated,
}

/// Artifact redaction state, kept orthogonal to profile compatibility.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactRedactionStateV1 {
    /// No required member was redacted.
    None,
    /// Authoritative evidence survives but protected views are unavailable.
    RedactedViews,
    /// Only minimized identity, ordering, and dependency structure survive.
    StructuralOnly,
    /// Required evidence is erased, invalidated, or otherwise unavailable.
    EvidenceMissing,
}

impl ArtifactRedactionStateV1 {
    const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::RedactedViews => 1,
            Self::StructuralOnly => 2,
            Self::EvidenceMissing => 3,
        }
    }

    /// Apply a redaction state without restoring previously unavailable evidence.
    #[must_use]
    pub const fn weakened_to(self, candidate: Self) -> Self {
        if self.rank() >= candidate.rank() {
            self
        } else {
            candidate
        }
    }
}

/// Immutable policy facts registered by the adapter that owns artifact bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegisteredArtifactV1 {
    /// Closed artifact class used by ADR-060 receipts.
    artifact_class: ErasureArtifactClassV1,
    /// Content identity of the registered artifact.
    artifact_digest: ErasureReferenceV1,
    /// Data class fixed before commit.
    data_class: ArtifactDataClassV1,
    /// Key role, when artifact availability depends on a role-separated key.
    key_role: Option<ErasureKeyRoleV1>,
    /// Registered adapter/owner identity.
    owner: ErasureReferenceV1,
    /// Whether the artifact is required by its enclosing claim.
    optionality: ArtifactOptionalityV1,
    /// One-way transition applied after a successful erasure acknowledgement.
    transition_rule: ArtifactTransitionRuleV1,
}

impl RegisteredArtifactV1 {
    /// Register the fixed policy facts for one artifact before commit.
    #[must_use]
    pub const fn new(
        artifact_class: ErasureArtifactClassV1,
        artifact_digest: ErasureReferenceV1,
        data_class: ArtifactDataClassV1,
        key_role: Option<ErasureKeyRoleV1>,
        owner: ErasureReferenceV1,
        optionality: ArtifactOptionalityV1,
        transition_rule: ArtifactTransitionRuleV1,
    ) -> Self {
        Self {
            artifact_class,
            artifact_digest,
            data_class,
            key_role,
            owner,
            optionality,
            transition_rule,
        }
    }

    /// Return the closed artifact class.
    #[must_use]
    pub const fn artifact_class(self) -> ErasureArtifactClassV1 {
        self.artifact_class
    }

    /// Return the content identity.
    #[must_use]
    pub const fn artifact_digest(self) -> ErasureReferenceV1 {
        self.artifact_digest
    }

    /// Return the pre-erasure data class.
    #[must_use]
    pub const fn data_class(self) -> ArtifactDataClassV1 {
        self.data_class
    }

    /// Return the optional role-separated key dependency.
    #[must_use]
    pub const fn key_role(self) -> Option<ErasureKeyRoleV1> {
        self.key_role
    }

    /// Return the registered byte-owner identity.
    #[must_use]
    pub const fn owner(self) -> ErasureReferenceV1 {
        self.owner
    }

    /// Return whether this artifact is required by its enclosing claim.
    #[must_use]
    pub const fn optionality(self) -> ArtifactOptionalityV1 {
        self.optionality
    }

    /// Return the transition rule fixed before erasure.
    #[must_use]
    pub const fn transition_rule(self) -> ArtifactTransitionRuleV1 {
        self.transition_rule
    }
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
    /// Closed class of the registered artifact.
    pub artifact_class: ErasureArtifactClassV1,
    /// Registered artifact identity.
    pub artifact_digest: ErasureReferenceV1,
    /// Claim before evaluation.
    pub from: ErasureReplayClaimV1,
    /// Claim after evaluation.
    pub to: ErasureReplayClaimV1,
    /// Redaction state independent of profile compatibility.
    pub redaction_state: ArtifactRedactionStateV1,
    /// Whether this exact state may be used as authoritative runtime input.
    pub authoritative_use_permitted: bool,
}

/// Aggregate result plus canonically ordered per-artifact transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayClaimEvaluationV1 {
    /// Weakest claim among required members and the enclosing claim.
    pub replay_claim: ErasureReplayClaimV1,
    /// Weakest redaction state among required members.
    pub redaction_state: ArtifactRedactionStateV1,
    /// Per-artifact results in canonical `(class, digest)` order.
    pub artifacts: Vec<EvaluatedArtifactClaimV1>,
}

impl ReplayClaimEvaluationV1 {
    /// Require a registered artifact to remain eligible as authoritative input.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::PolicyConflict`] when the artifact is absent,
    /// erased, structurally retained, quarantined by invalidation, or belongs
    /// to an evaluation whose required closure is no longer authoritative.
    pub fn require_authoritative_use(
        &self,
        artifact_class: ErasureArtifactClassV1,
        artifact_digest: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        if matches!(
            self.replay_claim,
            ErasureReplayClaimV1::StructuralOnly
                | ErasureReplayClaimV1::UnverifiableArtifactsMissing
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.artifacts
            .iter()
            .find(|artifact| {
                artifact.artifact_class == artifact_class
                    && artifact.artifact_digest == artifact_digest
            })
            .filter(|artifact| artifact.authoritative_use_permitted)
            .map_or(Err(ErasureErrorV1::PolicyConflict), |_| Ok(()))
    }
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
    /// Returns [`ErasureErrorV1::ScopeInvalid`] when the V1 closure bound is
    /// exceeded, or [`ErasureErrorV1::PolicyConflict`] for duplicate artifact
    /// identities.
    pub fn evaluate(
        enclosing_claim: ErasureReplayClaimV1,
        inputs: &[ArtifactClaimInputV1],
    ) -> Result<ReplayClaimEvaluationV1, ErasureErrorV1> {
        if inputs.len() > ERASURE_MAX_TARGETS {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
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
        let mut redaction_state = ArtifactRedactionStateV1::None;
        let artifacts = inputs
            .into_iter()
            .map(|input| {
                let (disposition_claim, artifact_redaction) = match input.state {
                    ArtifactStateV1::Retained => {
                        (input.current_claim, ArtifactRedactionStateV1::None)
                    }
                    ArtifactStateV1::TransitionApplied => {
                        input.registration.transition_rule.disposition()
                    }
                    ArtifactStateV1::MissingParentCut
                    | ArtifactStateV1::MissingFrozenInput
                    | ArtifactStateV1::MissingKey
                    | ArtifactStateV1::MissingSchema
                    | ArtifactStateV1::MissingPlugin
                    | ArtifactStateV1::MissingModel
                    | ArtifactStateV1::MissingRuntime
                    | ArtifactStateV1::MissingRequiredOutput
                    | ArtifactStateV1::Erased
                    | ArtifactStateV1::Invalidated => (
                        ErasureReplayClaimV1::UnverifiableArtifactsMissing,
                        ArtifactRedactionStateV1::EvidenceMissing,
                    ),
                };
                let to = input.current_claim.weakened_to(disposition_claim);
                if input.registration.optionality == ArtifactOptionalityV1::Required {
                    replay_claim = replay_claim.weakened_to(to);
                    redaction_state = redaction_state.weakened_to(artifact_redaction);
                }
                EvaluatedArtifactClaimV1 {
                    artifact_class: input.registration.artifact_class,
                    artifact_digest: input.registration.artifact_digest,
                    from: input.current_claim,
                    to,
                    redaction_state: artifact_redaction,
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
            redaction_state,
            artifacts,
        })
    }
}
