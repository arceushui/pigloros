//! Host-owned artifact registration and replay-claim evaluation.

use super::{
    ErasureArtifactClassV1, ErasureErrorV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ERASURE_MAX_TARGETS,
};
use crate::{Hash, KeyIdentityV1, KeyTombstoneV1};
use std::collections::BTreeMap;

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

/// Exact key material whose destruction may weaken a registered artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactKeyDependencyV1 {
    /// Owner-scoped key role and epoch fixed at artifact registration.
    pub identity: KeyIdentityV1,
    /// Fingerprint of the registered private material.
    pub material_digest: Hash,
    /// Whether reproducing this artifact needs the private bytes after commit.
    pub private_material_required: bool,
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
    /// Exact key dependency fixed before this artifact is committed.
    key_dependency: Option<ArtifactKeyDependencyV1>,
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
            key_dependency: None,
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

    /// Bind the exact role/epoch material required by this artifact.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::PolicyConflict`] when the dependency's role
    /// differs from the registered artifact role.
    pub fn with_key_dependency(
        mut self,
        dependency: ArtifactKeyDependencyV1,
    ) -> Result<Self, ErasureErrorV1> {
        let role = if dependency.identity.role.is_signing() {
            ErasureKeyRoleV1::Signing
        } else {
            ErasureKeyRoleV1::DataEncryption
        };
        if self.key_role != Some(role) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.key_dependency = Some(dependency);
        Ok(self)
    }

    /// Return the exact key dependency, if this artifact has one.
    #[must_use]
    pub const fn key_dependency(self) -> Option<ArtifactKeyDependencyV1> {
        self.key_dependency
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
    artifact_class: ErasureArtifactClassV1,
    /// Registered artifact identity.
    artifact_digest: ErasureReferenceV1,
    /// Claim before evaluation.
    from: ErasureReplayClaimV1,
    /// Claim after evaluation.
    to: ErasureReplayClaimV1,
    /// Redaction state independent of profile compatibility.
    redaction_state: ArtifactRedactionStateV1,
    /// Whether this exact state may be used as authoritative runtime input.
    authoritative_use_permitted: bool,
    /// Whether this member participates in the enclosing weakest-claim closure.
    optionality: ArtifactOptionalityV1,
}

impl EvaluatedArtifactClaimV1 {
    /// Return the evaluated artifact class.
    #[must_use]
    pub const fn artifact_class(&self) -> ErasureArtifactClassV1 {
        self.artifact_class
    }

    /// Return the evaluated artifact identity.
    #[must_use]
    pub const fn artifact_digest(&self) -> ErasureReferenceV1 {
        self.artifact_digest
    }

    /// Return the claim before evaluation.
    #[must_use]
    pub const fn from(&self) -> ErasureReplayClaimV1 {
        self.from
    }

    /// Return the claim after evaluation.
    #[must_use]
    pub const fn to(&self) -> ErasureReplayClaimV1 {
        self.to
    }

    /// Return the orthogonal redaction result.
    #[must_use]
    pub const fn redaction_state(&self) -> ArtifactRedactionStateV1 {
        self.redaction_state
    }

    /// Return whether the host evaluator admitted authoritative use.
    #[must_use]
    pub const fn authoritative_use_permitted(&self) -> bool {
        self.authoritative_use_permitted
    }

    /// Return whether this member is required by its enclosing claim.
    #[must_use]
    pub const fn optionality(&self) -> ArtifactOptionalityV1 {
        self.optionality
    }
}

/// Aggregate result plus canonically ordered per-artifact transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayClaimEvaluationV1 {
    /// Weakest claim among required members and the enclosing claim.
    replay_claim: ErasureReplayClaimV1,
    /// Weakest redaction state among required members.
    redaction_state: ArtifactRedactionStateV1,
    /// Per-artifact results in canonical `(class, digest)` order.
    artifacts: Vec<EvaluatedArtifactClaimV1>,
}

impl ReplayClaimEvaluationV1 {
    /// Return the weakest required-member replay claim.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.replay_claim
    }

    /// Return the weakest required-member redaction state.
    #[must_use]
    pub const fn redaction_state(&self) -> ArtifactRedactionStateV1 {
        self.redaction_state
    }

    /// Return the canonical per-artifact evaluation results.
    #[must_use]
    pub fn artifacts(&self) -> &[EvaluatedArtifactClaimV1] {
        &self.artifacts
    }

    /// Require every class in an enclosing artifact contract to be represented
    /// by at least one required member of this evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ScopeInvalid`] when a required class is absent.
    pub fn require_complete_classes(
        &self,
        required_classes: &[ErasureArtifactClassV1],
    ) -> Result<(), ErasureErrorV1> {
        if required_classes.iter().all(|required_class| {
            self.artifacts.iter().any(|artifact| {
                artifact.artifact_class == *required_class
                    && artifact.optionality == ArtifactOptionalityV1::Required
            })
        }) {
            Ok(())
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    }

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

/// Replay or `ReproManifest` authority after committed destruction facts have
/// been applied. Only the fact-aware evaluator can construct this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayArtifactAuthorizationV1 {
    evaluation: ReplayClaimEvaluationV1,
}

impl ReplayArtifactAuthorizationV1 {
    /// Return the weakest claim after key destruction is considered.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.evaluation.replay_claim()
    }

    /// Return the canonical per-artifact results.
    #[must_use]
    pub fn artifacts(&self) -> &[EvaluatedArtifactClaimV1] {
        self.evaluation.artifacts()
    }

    /// Require authoritative Replay or `ReproManifest` use after fact evaluation.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::PolicyConflict`] for a missing or weakened
    /// artifact, or for an unrelated artifact class.
    pub fn require_authoritative_use(
        &self,
        artifact_class: ErasureArtifactClassV1,
        artifact_digest: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        if !matches!(
            artifact_class,
            ErasureArtifactClassV1::TimelineReplay | ErasureArtifactClassV1::ReproManifest
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.evaluation
            .require_authoritative_use(artifact_class, artifact_digest)
    }
}

/// Sole host-owned policy evaluator for ADR-060 artifact claims.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayClaimEvaluatorV1;

impl ReplayClaimEvaluatorV1 {
    /// Evaluate Replay and `ReproManifest` artifacts against committed key
    /// destruction facts before permitting authoritative use. The caller must
    /// supply the complete fact set from its authoritative store.
    ///
    /// # Errors
    /// Returns [`ErasureErrorV1::PolicyConflict`] for duplicate or conflicting
    /// facts, or a key-role artifact lacking its exact registered dependency.
    pub fn evaluate_replay_artifacts(
        enclosing_claim: ErasureReplayClaimV1,
        inputs: &[ArtifactClaimInputV1],
        committed_facts: &[KeyTombstoneV1],
    ) -> Result<ReplayArtifactAuthorizationV1, ErasureErrorV1> {
        if inputs.is_empty() || inputs.len() > ERASURE_MAX_TARGETS {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let mut facts = BTreeMap::new();
        for fact in committed_facts {
            if facts.insert(fact.identity, *fact).is_some() {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        let mut checked = Vec::with_capacity(inputs.len());
        for input in inputs {
            let mut input = *input;
            if input.registration.key_role.is_some() && input.registration.key_dependency.is_none()
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            if let Some(dependency) = input.registration.key_dependency {
                if let Some(fact) = facts.get(&dependency.identity) {
                    if fact.destroyed_material_digest != dependency.material_digest {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    if dependency.private_material_required
                        && matches!(
                            input.state,
                            ArtifactStateV1::Retained | ArtifactStateV1::TransitionApplied
                        )
                    {
                        input.state = ArtifactStateV1::MissingKey;
                    }
                }
            }
            checked.push(input);
        }
        Self::evaluate(enclosing_claim, &checked)
            .map(|evaluation| ReplayArtifactAuthorizationV1 { evaluation })
    }

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
        if inputs.is_empty() || inputs.len() > ERASURE_MAX_TARGETS {
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
                    optionality: input.registration.optionality,
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
