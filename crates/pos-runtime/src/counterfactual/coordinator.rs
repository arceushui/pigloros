//! ADR-064 counterfactual admission through the first atomic Tick Boundary.
//!
//! [`CounterfactualCoordinatorV1`] is the core `CounterfactualCoordinator`
//! admission slice. It exclusively owns the Event Store that holds the
//! host-only [`CounterfactualStorePortV1`] capability, so no Driver, Plugin,
//! provider, or evaluator can reach that port through it. One call to
//! [`CounterfactualCoordinatorV1::admit`] validates, in this order, and
//! returns the first closed safe error:
//!
//! 1. the CFP1 [`CounterfactualPlanV1`] (bounds, Interventions, descriptors,
//!    and plan digest);
//! 2. the Fork append authority: an ADR-099 FAR1-admitted Fork is rejected
//!    as [`CounterfactualAdmissionErrorV1::ClassifiedForkUnsupported`];
//! 3. the authority and consent decision of every Intervention, in plan
//!    order, through the host [`CounterfactualInterventionAuthorityV1`];
//! 4. the EPF1 execution-profile and TPS1 trust-policy identities bound by
//!    the plan against the host-admitted records;
//! 5. the Fork: its committed generation, its recorded parent cut against
//!    the CFP1 parent Timeline and cut `Seq`, and its committed Logical Head;
//! 6. the closed dependency graph and the derived `RCF1` frontier, supplied
//!    by the host [`CounterfactualFrontierSourceV1`] and re-validated here;
//! 7. the `SIV1` invalidation built here, with its invalid-artifact index and
//!    cache/checkpoint eviction set;
//! 8. the first recomputation Tick, staged by the
//!    [`CounterfactualTickStagerV1`] from staged inputs only.
//!
//! Only then does it make exactly one
//! [`CounterfactualStorePortV1::commit_counterfactual_invalidation`] call.
//! The store rechecks the Fork head, plan digest, dependency-graph digest,
//! prior generation, and trust, revocation, and erasure epochs inside its
//! transaction; a mismatch returns
//! [`CounterfactualAdmissionErrorV1::InvalidationConflict`] and commits
//! nothing. Every earlier rejection commits nothing because the only write is
//! that one call. Success commits `RCF1`, `SIV1`, exactly one generation
//! increment, the index, the eviction set, and the first recomputation Tick
//! as one transaction, so readers never observe mixed generations.
//!
//! # ADR gap decisions
//!
//! - **Dependency cycle.** The graph validation and frontier derivation of
//!   ADR-064 live in `pos-time`, which depends on this crate. The coordinator
//!   therefore receives them through [`CounterfactualFrontierSourceV1`]: a
//!   host port that validates the closed dependency graph for the plan and
//!   derives the sealed `RCF1` frontier, and that reports every provisional
//!   output of the prior Fork generation. The coordinator never trusts the
//!   derivation: it re-runs the standalone `RCF1` validation, binds the
//!   frontier ID, plan, parent cut, classification bundle, provenance, and
//!   horizon, and checks the global frontier range. The dependency-graph
//!   digest is bound by the store, which rechecks it against the persisted
//!   graph digest.
//! - **ADR-099 classified Forks.** Both store adapters reserve every Event
//!   append to a FAR1-admitted Fork for the classifier append authority and
//!   would fail closed with `StorageFailure`. Classified provenance for the
//!   first recomputation Tick's Events is not designed yet, so the
//!   coordinator rejects such a Fork up front, before any store call. The
//!   host declares the Fork's append authority in the request; the store
//!   check stays as defense in depth. This is a deferred ADR-099 integration.
//! - **Parent Logical Head.** A Fork's parent cut is immutable once the Fork
//!   exists, so the coordinator validates the CFP1 parent Timeline and cut
//!   `Seq` against the Fork's recorded parent cut and reads the Fork's moving
//!   committed Logical Head, which the store rechecks atomically. A Fork
//!   whose topology cannot be read is reported as `ParentCutNotFound`.
//! - **Epochs.** The trust epoch is the TPS1 epoch of the plan, after the
//!   host TPS1 snapshot is proven to be the plan's. The revocation and erasure
//!   epochs are the host's current epochs. All three are rechecked by the
//!   store inside the transaction.
//! - **First recomputation Tick.** It is the `RCF1` global frontier Tick:
//!   Ticks between the parent cut and the frontier are unaffected and are not
//!   invalidated. The frontier must lie in `first_tick..=` the earliest
//!   Intervention effective Tick (`FrontierOutOfRange` otherwise).
//! - **`SIV1` fields.** The invalid start is the lowest affected node moved to
//!   the global frontier `(tick, scheduler_position)`; the inclusive end is the
//!   highest affected node moved to the endogenous suffix end Tick. The
//!   invalid artifacts are, per the complete-suffix rule, every provisional
//!   `EndogenousRecomputed` output of the prior generation at or after the
//!   global frontier `(tick, scheduler_position)`, with artifact class
//!   `EndogenousRecomputed`, in canonical producer order, duplicates merged.
//!   `PresentationOnly` outputs are excluded from the suffix claim. The
//!   retained descriptors are the ascending unique artifact digests of every
//!   `ExogenousFrozen` and `FixedPolicy` descriptor of the plan. The reason
//!   is `UnknownEdgeFallback` under `FullSuffixFromCut`, otherwise
//!   `ChangedIntervention` when the plan supersedes a previous plan, and
//!   `NewIntervention` otherwise. The commit coordinate is the Fork, its
//!   committed head before the first Tick, and the first recomputation Tick.
//!   `RCF1` and `SIV1` share the request's provenance digest.
//! - **Index and eviction set.** The index is the ascending unique digests of
//!   the invalid artifacts; the eviction set is the ascending union of the
//!   request's invalid checkpoint and Projection/snapshot digests.
//! - **Staged inputs.** The stager receives only an immutable
//!   [`CounterfactualTickInputsV1`]: the new generation coordinate, the Tick,
//!   the Interventions effective at that Tick, and the plan's frozen
//!   descriptors. It never receives the store, a prior-generation artifact,
//!   or uncommitted state, and its drafts become visible only through the
//!   atomic commit.

use std::collections::BTreeSet;

use pos_conformance::counterfactual::frontier_artifacts::{
    FrontierArtifactErrorV1, UnknownEdgeCoordinateV1,
};
use pos_conformance::counterfactual::plan::{
    CounterfactualPlanContractErrorV1, CounterfactualPlanV1, FrozenArtifactDescriptorV1,
    PlanExecutionProfileRefV1, PlanTrustPolicyRefV1,
};
use pos_conformance::counterfactual::InterventionV1;
use pos_conformance::{
    DependencyClassV1, DependencyNodeV1, ExecutionProfileV1, InvalidArtifactV1,
    RecomputationFrontierV1, SuffixInvalidationReasonV1, SuffixInvalidationV1,
    TrustPolicySnapshotV1, UnknownEdgePolicyV1,
};
use pos_core::{
    CounterfactualGenerationReceiptV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, EventDraft, EventStore,
    ForkGenerationV1, Hash, InvalidationConflictV1, PipelineContractErrorV1, PipelineDraftBatchV1,
    RecomputationFrontierBytesV1, Seq, SuffixInvalidationBytesV1, TimelineId,
};

/// `SIV1` artifact class of every invalidated endogenous output.
pub const ENDOGENOUS_ARTIFACT_CLASS_V1: &str = "EndogenousRecomputed";

/// Closed safe errors of counterfactual admission.
///
/// Errors carry only closed codes, the first canonical edge coordinate, or a
/// store conflict; no subject data is exposed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CounterfactualAdmissionErrorV1 {
    /// The CFP1 plan is invalid.
    #[error("counterfactual plan is invalid")]
    Plan(#[source] CounterfactualPlanContractErrorV1),
    /// The Fork is ADR-099 FAR1-admitted; classified first-Tick provenance is
    /// a deferred integration.
    #[error("counterfactual admission on a classified Fork is not supported")]
    ClassifiedForkUnsupported,
    /// The Principal or capability of an Intervention is not authorized.
    #[error("counterfactual Intervention is not authorized")]
    UnauthorizedIntervention,
    /// The consent decision of an Intervention is invalid.
    #[error("counterfactual Intervention consent is invalid")]
    ConsentInvalid,
    /// An Intervention targets state that cannot be intervened on.
    #[error("counterfactual Intervention target is not intervenable")]
    TargetNotIntervenable,
    /// The host EPF1 profile is invalid or is not the plan's profile.
    #[error("counterfactual execution profile is incompatible")]
    IncompatibleExecutionProfile,
    /// The host TPS1 snapshot is invalid or is not the plan's snapshot.
    #[error("counterfactual trust policy does not match the plan")]
    TrustPolicyMismatch,
    /// The Fork's recorded parent cut is absent or is not the plan's.
    #[error("counterfactual parent cut was not found")]
    ParentCutNotFound,
    /// A required direct dependency edge is missing under `Reject`.
    #[error("counterfactual dependency graph is incomplete")]
    DependencyGraphIncomplete(UnknownEdgeCoordinateV1),
    /// A dependency edge is undeclared or names an undeclared node.
    #[error("counterfactual dependency edge is unknown")]
    UnknownDependencyEdge(UnknownEdgeCoordinateV1),
    /// The dependency graph or its frontier derivation is otherwise invalid.
    #[error("counterfactual dependency graph is invalid")]
    DependencyGraphInvalid,
    /// The derived frontier violates the standalone `RCF1` contract.
    #[error("counterfactual frontier violates the RCF1 contract")]
    Frontier(#[source] FrontierArtifactErrorV1),
    /// The derived frontier does not bind the plan and request.
    #[error("counterfactual frontier does not bind the plan")]
    FrontierBindingMismatch,
    /// The global frontier lies before the first Tick or after the earliest
    /// Intervention.
    #[error("counterfactual frontier is out of range")]
    FrontierOutOfRange,
    /// The built invalidation violates the standalone `SIV1` contract.
    #[error("counterfactual invalidation violates the SIV1 contract")]
    Invalidation(#[source] FrontierArtifactErrorV1),
    /// The stager failed to stage the first recomputation Tick.
    #[error("counterfactual first Tick staging failed")]
    PluginFailure,
    /// The staged first-Tick drafts are empty, malformed, or oversized.
    #[error("counterfactual staged first Tick is invalid")]
    StagedTickRejected(#[source] PipelineContractErrorV1),
    /// A persisted fact changed before commit; nothing was committed.
    #[error("counterfactual invalidation conflicts with committed state")]
    InvalidationConflict(InvalidationConflictV1),
    /// The counterfactual store rejected or failed the operation.
    #[error("counterfactual store operation failed")]
    Store(#[source] CounterfactualStoreErrorV1),
}

/// Host-declared append authority of the Fork being admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualForkAppendAuthorityV1 {
    /// An ordinary Fork whose Events are appended through the generic path.
    Generic,
    /// An ADR-099 FAR1-admitted Fork whose appends are reserved for the
    /// classifier append authority; admission is deferred and rejected.
    ClassifiedAdmission,
}

/// The host's authority and consent decision for one Intervention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterventionDecisionV1 {
    /// The Principal, capability, and consent decision are valid.
    Authorized,
    /// The Principal or capability is not authorized.
    Unauthorized,
    /// The consent decision or consent epoch is invalid.
    ConsentInvalid,
    /// The target is consent, capability, trust, erasure, Timeline identity,
    /// audit integrity, or otherwise not intervenable.
    TargetNotIntervenable,
}

/// Host authority that decides every Intervention of a plan.
pub trait CounterfactualInterventionAuthorityV1 {
    /// Decide whether `intervention` may be admitted.
    fn decide(&self, intervention: &InterventionV1) -> InterventionDecisionV1;
}

/// One provisional output of the prior Fork generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualProvisionalOutputV1 {
    /// Exact producer node coordinate of the output.
    pub node: DependencyNodeV1,
    /// Closed ADR-064 class of the output.
    pub class: DependencyClassV1,
}

/// The graph-derived frontier and the prior generation's provisional outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualFrontierDerivationV1 {
    /// Sealed `RCF1` frontier derived from the validated dependency graph.
    pub frontier: RecomputationFrontierV1,
    /// Every provisional output of the prior generation, in any order.
    pub provisional_outputs: Vec<CounterfactualProvisionalOutputV1>,
}

/// Host port that validates the closed dependency graph and derives `RCF1`.
pub trait CounterfactualFrontierSourceV1 {
    /// Validate the Fork's closed dependency graph for `plan` and derive its
    /// sealed `RCF1` frontier with `frontier_id` and `provenance_digest`.
    ///
    /// # Errors
    /// Returns `DependencyGraphIncomplete`, `UnknownDependencyEdge`, or
    /// `DependencyGraphInvalid` for a rejected graph or derivation.
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, CounterfactualAdmissionErrorV1>;
}

/// Opaque failure of a stager; it carries no Plugin data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualTickFailureV1;

/// The staged, immutable inputs one recomputation Tick may read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfactualTickInputsV1<'a> {
    generation: ForkGenerationV1,
    tick: u64,
    interventions: &'a [InterventionV1],
    exogenous_descriptors: &'a [FrozenArtifactDescriptorV1],
    fixed_policy_descriptors: &'a [FrozenArtifactDescriptorV1],
}

impl<'a> CounterfactualTickInputsV1<'a> {
    /// Return the new Fork generation the Tick is staged under.
    #[must_use]
    pub const fn generation(&self) -> ForkGenerationV1 {
        self.generation
    }

    /// Return the recomputation Tick number.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Borrow the ordered Interventions effective at this Tick.
    #[must_use]
    pub const fn interventions(&self) -> &'a [InterventionV1] {
        self.interventions
    }

    /// Borrow the plan's `ExogenousFrozen` descriptors.
    #[must_use]
    pub const fn exogenous_descriptors(&self) -> &'a [FrozenArtifactDescriptorV1] {
        self.exogenous_descriptors
    }

    /// Borrow the plan's `FixedPolicy` descriptors.
    #[must_use]
    pub const fn fixed_policy_descriptors(&self) -> &'a [FrozenArtifactDescriptorV1] {
        self.fixed_policy_descriptors
    }
}

/// Driver/Plugin stage that produces one recomputation Tick's Event drafts.
pub trait CounterfactualTickStagerV1 {
    /// Stage the ordered Event drafts of one Tick from staged inputs only.
    ///
    /// # Errors
    /// Returns [`CounterfactualTickFailureV1`] when the Tick cannot be staged.
    fn stage_tick(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<Vec<EventDraft>, CounterfactualTickFailureV1>;
}

/// One counterfactual admission request.
#[derive(Clone, Copy)]
pub struct CounterfactualAdmissionRequestV1<'a> {
    /// CFP1 plan to admit.
    pub plan: &'a CounterfactualPlanV1,
    /// Fork Timeline whose suffix is invalidated.
    pub fork: TimelineId,
    /// Host-declared append authority of the Fork.
    pub fork_append_authority: CounterfactualForkAppendAuthorityV1,
    /// Host-admitted EPF1 execution profile.
    pub execution_profile: &'a ExecutionProfileV1,
    /// Host-admitted TPS1 trust-policy snapshot.
    pub trust_policy: &'a TrustPolicySnapshotV1,
    /// Current authority revocation epoch.
    pub revocation_epoch: u64,
    /// Current erasure epoch.
    pub erasure_epoch: u64,
    /// `RCF1` frontier ID.
    pub frontier_id: [u8; 16],
    /// `SIV1` invalidation ID.
    pub invalidation_id: [u8; 16],
    /// Provenance digest of the `RCF1` and `SIV1` records.
    pub provenance_digest: [u8; 32],
    /// Strictly ascending checkpoint digests of the prior generation.
    pub invalid_checkpoint_digests: &'a [[u8; 32]],
    /// Strictly ascending Projection/snapshot digests of the prior generation.
    pub invalid_projection_digests: &'a [[u8; 32]],
}

/// The core `CounterfactualCoordinator` admission slice.
///
/// It exclusively owns the store that holds the counterfactual port.
#[derive(Debug)]
pub struct CounterfactualCoordinatorV1<S> {
    store: S,
}

/// The Fork facts read before derivation.
#[derive(Clone, Copy)]
struct ForkBasisV1 {
    generation: u64,
    head: Seq,
}

/// The verified `SIV1` bytes with the index and eviction set derived from it.
struct InvalidationPartsV1 {
    bytes: SuffixInvalidationBytesV1,
    invalid_artifacts: Vec<Hash>,
    evictions: Vec<Hash>,
}

impl<S: EventStore + CounterfactualStorePortV1> CounterfactualCoordinatorV1<S> {
    /// Take exclusive ownership of the store that holds the port.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Borrow the store for generation-qualified reads.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Validate `request` and commit its invalidation and first recomputation
    /// Tick as one store transaction.
    ///
    /// See the module documentation for the validation order and rules.
    ///
    /// # Errors
    /// Returns the first closed safe error; every error commits nothing.
    pub fn admit(
        &mut self,
        request: &CounterfactualAdmissionRequestV1<'_>,
        authority: &impl CounterfactualInterventionAuthorityV1,
        frontier_source: &mut impl CounterfactualFrontierSourceV1,
        stager: &mut impl CounterfactualTickStagerV1,
    ) -> Result<CounterfactualGenerationReceiptV1, CounterfactualAdmissionErrorV1> {
        let plan = request.plan;
        plan.validate()
            .map_err(CounterfactualAdmissionErrorV1::Plan)?;
        if request.fork_append_authority == CounterfactualForkAppendAuthorityV1::ClassifiedAdmission
        {
            return Err(CounterfactualAdmissionErrorV1::ClassifiedForkUnsupported);
        }
        authorize(plan, authority)?;
        check_profile(request)?;
        let basis = fork_basis(&self.store, request)?;
        let derivation = frontier_source.derive_frontier(
            plan,
            request.frontier_id,
            request.provenance_digest,
        )?;
        let frontier = frontier_bytes(request, &derivation.frontier)?;
        let invalidation = invalidation_parts(request, basis, &derivation)?;
        let tick = derivation.frontier.global_frontier_tick;
        let drafts = stage_first_tick(stager, plan, invalidation.bytes.new_generation(), tick)?;
        let command =
            CounterfactualInvalidationCommandV1::try_new(CounterfactualInvalidationInputV1 {
                fork: request.fork,
                fork_logical_head: basis.head,
                trust_epoch: plan.trust_policy.epoch,
                revocation_epoch: request.revocation_epoch,
                erasure_epoch: request.erasure_epoch,
                frontier,
                invalidation: invalidation.bytes,
                invalid_artifacts: invalidation.invalid_artifacts,
                evictions: invalidation.evictions,
                first_tick: tick,
                first_tick_drafts: drafts,
            })
            .map_err(CounterfactualAdmissionErrorV1::Store)?;
        self.commit(&command)
    }

    /// Make the one store call and map its outcome.
    fn commit(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualGenerationReceiptV1, CounterfactualAdmissionErrorV1> {
        self.store
            .commit_counterfactual_invalidation(command)
            .map_err(CounterfactualAdmissionErrorV1::Store)
            .and_then(|outcome| match outcome {
                CounterfactualInvalidationOutcomeV1::Committed(receipt) => Ok(receipt),
                CounterfactualInvalidationOutcomeV1::InvalidationConflict(conflict) => Err(
                    CounterfactualAdmissionErrorV1::InvalidationConflict(conflict),
                ),
            })
    }
}

/// Decide every Intervention in plan order and return the first denial.
fn authorize(
    plan: &CounterfactualPlanV1,
    authority: &impl CounterfactualInterventionAuthorityV1,
) -> Result<(), CounterfactualAdmissionErrorV1> {
    plan.interventions
        .iter()
        .try_for_each(|intervention| match authority.decide(intervention) {
            InterventionDecisionV1::Authorized => Ok(()),
            InterventionDecisionV1::Unauthorized => {
                Err(CounterfactualAdmissionErrorV1::UnauthorizedIntervention)
            }
            InterventionDecisionV1::ConsentInvalid => {
                Err(CounterfactualAdmissionErrorV1::ConsentInvalid)
            }
            InterventionDecisionV1::TargetNotIntervenable => {
                Err(CounterfactualAdmissionErrorV1::TargetNotIntervenable)
            }
        })
}

/// Prove the host EPF1 and TPS1 records are the ones the plan binds.
fn check_profile(
    request: &CounterfactualAdmissionRequestV1<'_>,
) -> Result<(), CounterfactualAdmissionErrorV1> {
    let plan = request.plan;
    let profile = PlanExecutionProfileRefV1::from_execution_profile_v1(request.execution_profile);
    if profile.as_ref().ok() != Some(&plan.execution_profile) {
        return Err(CounterfactualAdmissionErrorV1::IncompatibleExecutionProfile);
    }
    let trust = PlanTrustPolicyRefV1::from_trust_policy_snapshot_v1(request.trust_policy);
    if trust.as_ref().ok() != Some(&plan.trust_policy) {
        return Err(CounterfactualAdmissionErrorV1::TrustPolicyMismatch);
    }
    Ok(())
}

/// Read the Fork generation, check its parent cut, and read its head.
fn fork_basis<S: EventStore + CounterfactualStorePortV1>(
    store: &S,
    request: &CounterfactualAdmissionRequestV1<'_>,
) -> Result<ForkBasisV1, CounterfactualAdmissionErrorV1> {
    let fork = request.fork;
    let expected = Some((request.plan.parent_timeline_id, request.plan.parent_cut_seq));
    store
        .current_fork_generation(fork)
        .map_err(CounterfactualAdmissionErrorV1::Store)
        .and_then(|generation| {
            let parent_cut = store
                .get_timeline(fork)
                .ok()
                .flatten()
                .and_then(|timeline| timeline.meta.fork_point)
                .map(|(parent, seq)| (parent.inner().to_bytes(), seq.as_u64()));
            if parent_cut == expected {
                store
                    .logical_head(fork)
                    .map(|head| ForkBasisV1 {
                        generation: generation.generation,
                        head,
                    })
                    .or(Err(CounterfactualAdmissionErrorV1::Store(
                        CounterfactualStoreErrorV1::StorageFailure,
                    )))
            } else {
                Err(CounterfactualAdmissionErrorV1::ParentCutNotFound)
            }
        })
}

/// Re-validate the derived frontier, bind it, and verify its exact bytes.
fn frontier_bytes(
    request: &CounterfactualAdmissionRequestV1<'_>,
    frontier: &RecomputationFrontierV1,
) -> Result<RecomputationFrontierBytesV1, CounterfactualAdmissionErrorV1> {
    let bytes = frontier
        .to_canonical_cbor()
        .map_err(CounterfactualAdmissionErrorV1::Frontier)?;
    check_frontier(request, frontier)?;
    RecomputationFrontierBytesV1::try_from_canonical(bytes)
        .map_err(CounterfactualAdmissionErrorV1::Store)
}

/// Bind the frontier to the plan and request and check its global range.
fn check_frontier(
    request: &CounterfactualAdmissionRequestV1<'_>,
    frontier: &RecomputationFrontierV1,
) -> Result<(), CounterfactualAdmissionErrorV1> {
    let plan = request.plan;
    let bound = (
        frontier.frontier_id,
        frontier.plan_digest,
        frontier.parent_cut_digest,
        frontier.classification_bundle_digest,
        frontier.provenance_digest,
        frontier.endogenous_suffix_end_tick,
    );
    let expected = (
        request.frontier_id,
        plan.plan_digest,
        plan.parent_cut_digest,
        plan.classification_bundle_digest,
        request.provenance_digest,
        plan.horizon_tick,
    );
    if bound != expected {
        return Err(CounterfactualAdmissionErrorV1::FrontierBindingMismatch);
    }
    // A validated plan holds at least one Intervention, ordered by Tick.
    let earliest = plan.interventions[0].effective_tick;
    if frontier.global_frontier_tick < plan.first_tick || frontier.global_frontier_tick > earliest {
        return Err(CounterfactualAdmissionErrorV1::FrontierOutOfRange);
    }
    Ok(())
}

/// Build, seal, and verify `SIV1`, and derive its index and eviction set.
fn invalidation_parts(
    request: &CounterfactualAdmissionRequestV1<'_>,
    basis: ForkBasisV1,
    derivation: &CounterfactualFrontierDerivationV1,
) -> Result<InvalidationPartsV1, CounterfactualAdmissionErrorV1> {
    let plan = request.plan;
    let frontier = &derivation.frontier;
    let fork_id = request.fork.inner().to_bytes();
    let reason = invalidation_reason(plan, frontier);
    let unsigned = SuffixInvalidationV1 {
        invalidation_id: request.invalidation_id,
        plan_digest: plan.plan_digest,
        fork_id,
        prior_generation: basis.generation,
        new_generation: basis.generation.wrapping_add(1),
        frontier_digest: frontier.frontier_digest,
        invalid_start: invalid_start(frontier),
        invalid_end: invalid_end(frontier),
        invalid_artifacts: invalid_artifacts(derivation, basis.generation, reason),
        invalid_checkpoint_digests: request.invalid_checkpoint_digests.to_vec(),
        invalid_projection_digests: request.invalid_projection_digests.to_vec(),
        retained_exogenous_digests: retained_descriptors(plan),
        reason,
        commit_timeline_id: fork_id,
        commit_seq: basis.head.as_u64(),
        commit_tick: frontier.global_frontier_tick,
        provenance_digest: request.provenance_digest,
        invalidation_digest: [0; 32],
    };
    let invalid_artifacts = digest_set(
        unsigned
            .invalid_artifacts
            .iter()
            .map(|artifact| artifact.artifact_digest),
    );
    let evictions = digest_set(
        request
            .invalid_checkpoint_digests
            .iter()
            .chain(request.invalid_projection_digests)
            .copied(),
    );
    seal_invalidation(unsigned).and_then(|bytes| {
        SuffixInvalidationBytesV1::try_from_canonical(bytes)
            .map_err(CounterfactualAdmissionErrorV1::Store)
            .map(|bytes| InvalidationPartsV1 {
                bytes,
                invalid_artifacts,
                evictions,
            })
    })
}

/// Fill the invalidation digest, then run the standalone `SIV1` validation.
fn seal_invalidation(
    unsigned: SuffixInvalidationV1,
) -> Result<Vec<u8>, CounterfactualAdmissionErrorV1> {
    unsigned
        .digest()
        .and_then(|invalidation_digest| {
            SuffixInvalidationV1 {
                invalidation_digest,
                ..unsigned
            }
            .to_canonical_cbor()
        })
        .map_err(CounterfactualAdmissionErrorV1::Invalidation)
}

const fn invalidation_reason(
    plan: &CounterfactualPlanV1,
    frontier: &RecomputationFrontierV1,
) -> SuffixInvalidationReasonV1 {
    if matches!(
        frontier.unknown_edge_policy,
        UnknownEdgePolicyV1::FullSuffixFromCut
    ) {
        SuffixInvalidationReasonV1::UnknownEdgeFallback
    } else if plan.previous_plan_digest.is_some() {
        SuffixInvalidationReasonV1::ChangedIntervention
    } else {
        SuffixInvalidationReasonV1::NewIntervention
    }
}

/// The lowest affected node moved to the global frontier.
fn invalid_start(frontier: &RecomputationFrontierV1) -> DependencyNodeV1 {
    DependencyNodeV1 {
        tick: frontier.global_frontier_tick,
        scheduler_position: frontier.global_frontier_scheduler_position,
        ..frontier.affected_nodes[0].clone()
    }
}

/// The highest affected node moved to the endogenous suffix end Tick.
fn invalid_end(frontier: &RecomputationFrontierV1) -> DependencyNodeV1 {
    let highest = frontier.affected_nodes.len() - 1;
    DependencyNodeV1 {
        tick: frontier.endogenous_suffix_end_tick,
        ..frontier.affected_nodes[highest].clone()
    }
}

/// Every provisional endogenous output at or after the global frontier, in
/// canonical producer order with duplicates merged.
fn invalid_artifacts(
    derivation: &CounterfactualFrontierDerivationV1,
    prior_generation: u64,
    reason: SuffixInvalidationReasonV1,
) -> Vec<InvalidArtifactV1> {
    let global = (
        derivation.frontier.global_frontier_tick,
        derivation.frontier.global_frontier_scheduler_position,
    );
    derivation
        .provisional_outputs
        .iter()
        .filter(|output| {
            output.class == DependencyClassV1::EndogenousRecomputed
                && (output.node.tick, output.node.scheduler_position) >= global
        })
        .map(|output| &output.node)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|producer| InvalidArtifactV1 {
            artifact_class: ENDOGENOUS_ARTIFACT_CLASS_V1.to_owned(),
            schema_id: producer.schema_id,
            artifact_digest: producer.artifact_digest,
            producer: producer.clone(),
            prior_generation,
            reason,
        })
        .collect()
}

/// Ascending unique artifact digests of every frozen and fixed descriptor.
fn retained_descriptors(plan: &CounterfactualPlanV1) -> Vec<[u8; 32]> {
    plan.exogenous_descriptors
        .iter()
        .chain(&plan.fixed_policy_descriptors)
        .map(|descriptor| descriptor.artifact_digest)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn digest_set(digests: impl Iterator<Item = [u8; 32]>) -> Vec<Hash> {
    digests
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Hash::from_bytes)
        .collect()
}

/// Stage the first recomputation Tick from staged inputs only.
fn stage_first_tick(
    stager: &mut impl CounterfactualTickStagerV1,
    plan: &CounterfactualPlanV1,
    generation: ForkGenerationV1,
    tick: u64,
) -> Result<PipelineDraftBatchV1, CounterfactualAdmissionErrorV1> {
    let start = plan
        .interventions
        .partition_point(|intervention| intervention.effective_tick < tick);
    let end = plan
        .interventions
        .partition_point(|intervention| intervention.effective_tick <= tick);
    let inputs = CounterfactualTickInputsV1 {
        generation,
        tick,
        interventions: &plan.interventions[start..end],
        exogenous_descriptors: &plan.exogenous_descriptors,
        fixed_policy_descriptors: &plan.fixed_policy_descriptors,
    };
    stager
        .stage_tick(&inputs)
        .or(Err(CounterfactualAdmissionErrorV1::PluginFailure))
        .and_then(|drafts| {
            PipelineDraftBatchV1::try_new(drafts)
                .map_err(CounterfactualAdmissionErrorV1::StagedTickRejected)
        })
}
