//! ADR-060 erasure conformance cases (ADR-062 Revision 8 slice N5, #1233).
//!
//! The owner note `ADR-062_R8_Erasure_Cases` fixes the slice: every case of
//! `fixtures/conformance/erasure/cases.json` runs through the public
//! [`ErasureExecutionHostV1`] command and read senders, over `MemoryStore` and
//! `SQLite`, with the fixture-only coordinator authority of this module
//! ([`FixtureErasureAuthorityV1`]). The cases, the exact `ERQ1` request bytes
//! and the expected projection are written by the independent generator
//! `scripts/generate_erasure_conformance_fixtures.py`; this module only
//! executes them and returns the `ERQ1`, `ERS1`, `ERC1` and `ERRJ1` records.
//!
//! One case runs:
//! 1. Optionally the policy-conflict prefix: the original request is
//!    submitted, its authorization is refused with `PolicyConflict`, it is
//!    `Rejected`, and the corrected request (bound to an
//!    `ErasureCorrectionProvenanceV1`) is submitted in its place.
//! 2. Submit (when not corrected), authorize and freeze access at the case's
//!    Tick Boundary. The authority freezes the case's target closure and its
//!    applicable `(category, target)` obligations; every other pair is
//!    `Inapplicable`, which is how a legal hold is expressed.
//! 3. Each attempt: dispatch the retry admission of the unresolved
//!    obligations, deliver the acknowledgements in arrival order, evaluate
//!    each inventory row with [`ReplayClaimEvaluatorV1`] starting from the
//!    previous receipt's claim, and finalize one `ERC1`.
//! 4. Each rejoin proof is admitted, or refused, against its receipt.
//!
//! This is engineering evidence of one host, not distributed replica,
//! backup or rejoin behaviour, and it makes no ADR-059 mode claim.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use pos_core::erasure::{
    destruction_command_reference, target_closure_digest, ArtifactClaimInputV1,
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionV1, ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1,
    ErasureAuthorizationDecisionV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkScopeRequirementV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1, ErasureHostErrorV1,
    ErasureInventoryCategoryV1, ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1,
    ErasureObligationInputV1, ErasureObligationSetInputV1, ErasureObligationSetV1,
    ErasureObligationV1, ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureRejoinAdmissionV1, ErasureRejoinAttestationVerifierV1, ErasureRejoinDispositionV1,
    ErasureRejoinInventoryV1, ErasureRejoinProofInputV1, ErasureRejoinProofV1,
    ErasureReplayClaimV1, ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureStateTransitionV1,
    ErasureStateV1, ErasureVerifiedTopologyObservationV1, RegisteredArtifactV1,
    ReplayClaimEvaluatorV1,
};
use pos_core::{TimelineId, TimelineMeta};
use pos_runtime::{
    ErasureCoordinatorAuthorityV1, ErasureCoordinatorCompositionV1, ErasureExecutionHostV1,
};
use pos_store::StoreConfig;
use serde::{Deserialize, Deserializer};

/// One 32-byte digest of the case catalogue, written as 64 hex digits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureCaseDigestV1(pub [u8; 32]);

impl ErasureCaseDigestV1 {
    /// Return the digest as an erasure reference.
    #[must_use]
    pub const fn reference(self) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest(self.0)
    }
}

impl<'de> Deserialize<'de> for ErasureCaseDigestV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).and_then(|text| {
            decode_digest(&text)
                .map(Self)
                .ok_or_else(|| serde::de::Error::custom("expected 64 hex digits"))
        })
    }
}

fn decode_digest(text: &str) -> Option<[u8; 32]> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            text.get(index..index + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .and_then(|bytes| bytes.try_into().ok())
}

/// The complete case catalogue (`cases.json`).
#[derive(Clone, Debug, Deserialize)]
pub struct ErasureCaseCatalogueV1 {
    /// Coordinator identity of every case.
    pub coordinator: ErasureCaseDigestV1,
    /// Pinned policy revision of every request, obligation set and attempt.
    pub policy: ErasureCaseDigestV1,
    /// Pinned trust revision of every obligation set and attempt.
    pub trust: ErasureCaseDigestV1,
    /// The scope member every case freezes.
    pub scope_member: ErasureCaseDigestV1,
    /// The lineage rule every scope commitment binds.
    pub lineage_rule: ErasureCaseDigestV1,
    /// The quota reservation identity granted to every attempt.
    pub quota_reservation: ErasureCaseDigestV1,
    /// The only rejoin attestation the fixture verifier authenticates.
    pub rejoin_attestation: ErasureCaseDigestV1,
    /// The cases, in catalogue order.
    pub cases: Vec<ErasureCaseV1>,
}

/// One erasure case.
#[derive(Clone, Debug, Deserialize)]
pub struct ErasureCaseV1 {
    /// Stable case identity.
    pub case_id: String,
    /// The exact `ERQ1` file, relative to the erasure fixture root.
    pub request: String,
    /// The policy-conflict prefix, when the original request is refused.
    pub policy_conflict: Option<ErasureCasePolicyConflictV1>,
    /// Provenance of the authorization decision.
    pub authorization_provenance: ErasureCaseDigestV1,
    /// Provenance of the requested access freeze.
    pub freeze_provenance: ErasureCaseDigestV1,
    /// The target closure in canonical ADR-060 order.
    pub targets: Vec<ErasureCaseTargetV1>,
    /// The applicable `(category, target)` obligations; every other pair is
    /// `Inapplicable`.
    pub obligations: Vec<ErasureCaseObligationV1>,
    /// The destruction attempts, attempt 0 first.
    pub attempts: Vec<ErasureCaseAttemptV1>,
    /// The rejoin proofs checked against the final request's receipts.
    pub rejoins: Vec<ErasureCaseRejoinV1>,
}

/// The refused original request of a policy-conflict case.
#[derive(Clone, Debug, Deserialize)]
pub struct ErasureCasePolicyConflictV1 {
    /// Provenance of the rejection decision.
    pub rejection_provenance: ErasureCaseDigestV1,
    /// Reason bound into the correction provenance.
    pub correction_reason: ErasureCaseDigestV1,
    /// Authorization provenance bound into the correction provenance.
    pub correction_authorization: ErasureCaseDigestV1,
    /// The corrected `ERQ1` file, relative to the erasure fixture root.
    pub request: String,
}

/// One target of the frozen closure.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ErasureCaseTargetV1 {
    /// Artifact class.
    pub artifact_class: ErasureCaseArtifactClassV1,
    /// Artifact identity digest.
    pub artifact_digest: ErasureCaseDigestV1,
    /// Key role.
    pub key_role: ErasureCaseKeyRoleV1,
    /// Key identity digest.
    pub key_digest: ErasureCaseDigestV1,
    /// Registered replica set.
    pub replica_set: ErasureCaseDigestV1,
    /// Registered replica.
    pub replica_id: ErasureCaseDigestV1,
}

impl ErasureCaseTargetV1 {
    /// Return the `ErasureRequiredTargetV1` of this target.
    #[must_use]
    pub const fn target(self) -> ErasureRequiredTargetV1 {
        ErasureRequiredTargetV1 {
            artifact_class: self.artifact_class.class(),
            artifact_digest: self.artifact_digest.reference(),
            key_role: self.key_role.role(),
            key_digest: self.key_digest.reference(),
            replica_set: self.replica_set.reference(),
            replica_id: self.replica_id.reference(),
        }
    }
}

/// One applicable obligation.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ErasureCaseObligationV1 {
    /// Owner category.
    pub category: ErasureCaseCategoryV1,
    /// Index into [`ErasureCaseV1::targets`].
    pub target: usize,
    /// Category-scoped owner identity.
    pub owner: ErasureCaseDigestV1,
}

/// One destruction attempt.
#[derive(Clone, Debug, Deserialize)]
pub struct ErasureCaseAttemptV1 {
    /// Authorization provenance of the retry admission.
    pub authorization_provenance: ErasureCaseDigestV1,
    /// Receipt signature commitment.
    pub signature: ErasureCaseDigestV1,
    /// Owner acknowledgements in arrival order (duplicates allowed).
    pub acknowledgements: Vec<ErasureCaseAcknowledgementV1>,
    /// One inventory row per obligation.
    pub rows: Vec<ErasureCaseRowV1>,
}

/// One owner acknowledgement.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ErasureCaseAcknowledgementV1 {
    /// Index into [`ErasureCaseV1::obligations`].
    pub obligation: usize,
    /// Local outcome.
    pub outcome: ErasureCaseOutcomeV1,
    /// Command evidence digest.
    pub evidence: ErasureCaseDigestV1,
}

/// One `ERC1` inventory row: the artifact's registered transition rule and
/// its owner-reported state.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ErasureCaseRowV1 {
    /// Index into [`ErasureCaseV1::obligations`].
    pub obligation: usize,
    /// Transition rule fixed before erasure.
    pub rule: ErasureCaseRuleV1,
    /// Owner-reported artifact state.
    pub state: ErasureCaseStateV1,
    /// Transition reason digest.
    pub reason: ErasureCaseDigestV1,
    /// Acknowledgement commitment digest.
    pub acknowledgements: ErasureCaseDigestV1,
    /// Transition provenance digest.
    pub provenance: ErasureCaseDigestV1,
    /// Retained-disclosure digest.
    pub retained_disclosure: ErasureCaseDigestV1,
}

/// One rejoin proof.
#[derive(Clone, Debug, Deserialize)]
pub struct ErasureCaseRejoinV1 {
    /// Index of the receipt (attempt) the proof is admitted against.
    pub attempt: usize,
    /// Inventory generation of the rejoining replica.
    pub inventory_generation: ErasureCaseDigestV1,
    /// Attestation of the proof.
    pub attestation: ErasureCaseDigestV1,
    /// Replica and backup assertions.
    pub entries: Vec<ErasureCaseRejoinEntryV1>,
}

/// One rejoin assertion.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ErasureCaseRejoinEntryV1 {
    /// Index into [`ErasureCaseV1::obligations`] (a replica or backup one).
    pub obligation: usize,
    /// No-resurrection disposition.
    pub disposition: ErasureCaseDispositionV1,
    /// Evidence digest.
    pub evidence: ErasureCaseDigestV1,
}

/// `ErasureArtifactClassV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseArtifactClassV1 {
    /// Timeline or Replay evidence.
    TimelineReplay,
    /// Reproducibility manifest.
    ReproManifest,
    /// Causal trace.
    CausalTrace,
    /// Calibration Report.
    CalibrationReport,
    /// Export.
    Export,
    /// Fork, snapshot or counterfactual artifact.
    ForkOrSnapshot,
    /// Conformance evidence.
    ConformanceReport,
}

impl ErasureCaseArtifactClassV1 {
    const fn class(self) -> ErasureArtifactClassV1 {
        match self {
            Self::TimelineReplay => ErasureArtifactClassV1::TimelineReplay,
            Self::ReproManifest => ErasureArtifactClassV1::ReproManifest,
            Self::CausalTrace => ErasureArtifactClassV1::CausalTrace,
            Self::CalibrationReport => ErasureArtifactClassV1::CalibrationReport,
            Self::Export => ErasureArtifactClassV1::Export,
            Self::ForkOrSnapshot => ErasureArtifactClassV1::ForkOrSnapshot,
            Self::ConformanceReport => ErasureArtifactClassV1::ConformanceReport,
        }
    }
}

/// `ErasureKeyRoleV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseKeyRoleV1 {
    /// Data-encryption key.
    DataEncryption,
    /// Signing key.
    Signing,
    /// Backup envelope key.
    BackupEnvelope,
    /// Replica transport key.
    ReplicaTransport,
}

impl ErasureCaseKeyRoleV1 {
    const fn role(self) -> ErasureKeyRoleV1 {
        match self {
            Self::DataEncryption => ErasureKeyRoleV1::DataEncryption,
            Self::Signing => ErasureKeyRoleV1::Signing,
            Self::BackupEnvelope => ErasureKeyRoleV1::BackupEnvelope,
            Self::ReplicaTransport => ErasureKeyRoleV1::ReplicaTransport,
        }
    }
}

/// `ErasureInventoryCategoryV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseCategoryV1 {
    /// Registered artifact owner.
    Artifact,
    /// Authoritative key registry.
    Key,
    /// Replica-local owner.
    Replica,
    /// Backup inventory owner.
    Backup,
}

impl ErasureCaseCategoryV1 {
    const fn category(self) -> ErasureInventoryCategoryV1 {
        match self {
            Self::Artifact => ErasureInventoryCategoryV1::Artifact,
            Self::Key => ErasureInventoryCategoryV1::Key,
            Self::Replica => ErasureInventoryCategoryV1::Replica,
            Self::Backup => ErasureInventoryCategoryV1::Backup,
        }
    }
}

/// `ErasureAcknowledgementOutcomeV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseOutcomeV1 {
    /// Owner completed scoped work.
    Acknowledged,
    /// Owner could not complete scoped work.
    Negative,
    /// Owner evidence is stale.
    Stale,
}

impl ErasureCaseOutcomeV1 {
    const fn outcome(self) -> ErasureAcknowledgementOutcomeV1 {
        match self {
            Self::Acknowledged => ErasureAcknowledgementOutcomeV1::Acknowledged,
            Self::Negative => ErasureAcknowledgementOutcomeV1::Negative,
            Self::Stale => ErasureAcknowledgementOutcomeV1::Stale,
        }
    }
}

/// `ArtifactTransitionRuleV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseRuleV1 {
    /// No erased material; the artifact stays exact.
    PreserveExact,
    /// Viewer fields disappear; authoritative evidence survives.
    RedactViews,
    /// Only structural identity and ordering survive.
    RetainStructure,
    /// Required bytes or keys are destroyed.
    Remove,
}

impl ErasureCaseRuleV1 {
    const fn rule(self) -> ArtifactTransitionRuleV1 {
        match self {
            Self::PreserveExact => ArtifactTransitionRuleV1::PreserveExact,
            Self::RedactViews => ArtifactTransitionRuleV1::RedactViews,
            Self::RetainStructure => ArtifactTransitionRuleV1::RetainStructure,
            Self::Remove => ArtifactTransitionRuleV1::Remove,
        }
    }
}

/// `ArtifactStateV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseStateV1 {
    /// Original bytes and keys remain.
    Retained,
    /// The registered transition rule was applied.
    TransitionApplied,
    /// The parent Timeline cut is unavailable.
    MissingParentCut,
    /// A frozen exogenous input is unavailable.
    MissingFrozenInput,
    /// A required key is unavailable.
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
    /// The artifact was erased.
    Erased,
    /// The artifact's generation is quarantined.
    Invalidated,
}

impl ErasureCaseStateV1 {
    const fn state(self) -> ArtifactStateV1 {
        match self {
            Self::Retained => ArtifactStateV1::Retained,
            Self::TransitionApplied => ArtifactStateV1::TransitionApplied,
            Self::MissingParentCut => ArtifactStateV1::MissingParentCut,
            Self::MissingFrozenInput => ArtifactStateV1::MissingFrozenInput,
            Self::MissingKey => ArtifactStateV1::MissingKey,
            Self::MissingSchema => ArtifactStateV1::MissingSchema,
            Self::MissingPlugin => ArtifactStateV1::MissingPlugin,
            Self::MissingModel => ArtifactStateV1::MissingModel,
            Self::MissingRuntime => ArtifactStateV1::MissingRuntime,
            Self::MissingRequiredOutput => ArtifactStateV1::MissingRequiredOutput,
            Self::Erased => ArtifactStateV1::Erased,
            Self::Invalidated => ArtifactStateV1::Invalidated,
        }
    }
}

/// `ErasureRejoinDispositionV1` as named in the catalogue.
#[derive(Clone, Copy, Debug, Deserialize)]
pub enum ErasureCaseDispositionV1 {
    /// The target is destroyed and tombstoned.
    Tombstoned,
    /// The target cannot be recovered by the replica or its backups.
    Unrecoverable,
}

impl ErasureCaseDispositionV1 {
    const fn disposition(self) -> ErasureRejoinDispositionV1 {
        match self {
            Self::Tombstoned => ErasureRejoinDispositionV1::Tombstoned,
            Self::Unrecoverable => ErasureRejoinDispositionV1::Unrecoverable,
        }
    }
}

/// A closed, payload-free failure of one case execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureCaseErrorV1 {
    /// A request file could not be read.
    Read(std::io::ErrorKind),
    /// A record of the case violates an ADR-060 invariant.
    Fixture(ErasureErrorV1),
    /// The public host refused a command.
    Host(ErasureHostErrorV1),
    /// The case names an obligation, target or attempt it does not have.
    InvalidIndex,
    /// The host returned no `ERS1` history for a submitted request.
    MissingHistory,
}

impl std::fmt::Display for ErasureCaseErrorV1 {
    /// Closed, payload-free text: no request, record or subject bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(kind) => write!(formatter, "erasure case request unreadable: {kind}"),
            Self::Fixture(error) => write!(formatter, "erasure case record refused: {error}"),
            Self::Host(error) => write!(formatter, "erasure case command refused: {error}"),
            Self::InvalidIndex => formatter.write_str("erasure case index outside the case"),
            Self::MissingHistory => formatter.write_str("erasure case has no ERS1 history"),
        }
    }
}

impl From<std::io::Error> for ErasureCaseErrorV1 {
    fn from(error: std::io::Error) -> Self {
        Self::Read(error.kind())
    }
}

/// The `ERS1` history and `ERC1` receipts of one request.
#[derive(Clone, Debug)]
pub struct ErasureCaseHistoryV1 {
    /// The host's refusal of the authorization, if it refused it.
    pub authorization_refusal: Option<ErasureHostErrorV1>,
    /// The request.
    pub request: ErasureRequestV1,
    /// The verified `ERS1` chain, oldest first.
    pub states: Vec<ErasureStateV1>,
    /// One `ERC1` per finalized attempt.
    pub receipts: Vec<ErasureReceiptV1>,
}

/// One rejoin proof and its admission outcome.
#[derive(Clone, Debug)]
pub struct ErasureCaseRejoinRecordV1 {
    /// The `ERRJ1` proof.
    pub proof: ErasureRejoinProofV1,
    /// The admission token, or the closed refusal.
    pub outcome: Result<ErasureRejoinAdmissionV1, ErasureErrorV1>,
}

/// Every record one case produced.
#[derive(Clone, Debug)]
pub struct ErasureCaseRecordV1 {
    /// One history per request; the refused original comes first.
    pub histories: Vec<ErasureCaseHistoryV1>,
    /// The rejoin proofs in case order.
    pub rejoins: Vec<ErasureCaseRejoinRecordV1>,
}

/// The fixture obligations of `case` for one request, in case order.
///
/// # Errors
/// Returns [`ErasureCaseErrorV1::Fixture`] with `ScopeInvalid` for a target
/// index outside the closure, or with the closed obligation error.
pub fn case_obligations(
    case: &ErasureCaseV1,
    request: ErasureReferenceV1,
) -> Result<Vec<ErasureObligationV1>, ErasureCaseErrorV1> {
    obligations_for(case, request).map_err(ErasureCaseErrorV1::Fixture)
}

fn obligations_for(
    case: &ErasureCaseV1,
    request: ErasureReferenceV1,
) -> Result<Vec<ErasureObligationV1>, ErasureErrorV1> {
    case.obligations
        .iter()
        .map(|obligation| {
            case.targets
                .get(obligation.target)
                .ok_or(ErasureErrorV1::ScopeInvalid)
                .and_then(|target| {
                    let target = target.target();
                    ErasureObligationV1::new(ErasureObligationInputV1 {
                        category: obligation.category.category(),
                        target,
                        owner: obligation.owner.reference(),
                        command_identity: destruction_command_reference(request, target),
                    })
                })
        })
        .collect()
}

/// The repository fixture-only coordinator authority of one case.
///
/// It authenticates every request, refuses the authorization of the case's
/// conflicted request with `PolicyConflict`, freezes the case's target
/// closure and obligations, binds every Timeline it is told about (and every
/// Fork of one) to the frozen scope, and admits every attempt,
/// acknowledgement and receipt.
pub struct FixtureErasureAuthorityV1 {
    catalogue: ErasureCaseCatalogueV1,
    case: ErasureCaseV1,
    conflicted_request: Option<ErasureReferenceV1>,
    frozen: Mutex<Option<ErasureReferenceV1>>,
    timelines: Mutex<BTreeSet<TimelineId>>,
}

impl FixtureErasureAuthorityV1 {
    /// Build the authority of `case`; `conflicted_request` is refused.
    #[must_use]
    pub fn new(
        catalogue: &ErasureCaseCatalogueV1,
        case: &ErasureCaseV1,
        conflicted_request: Option<ErasureReferenceV1>,
    ) -> Self {
        Self {
            catalogue: ErasureCaseCatalogueV1 {
                cases: Vec::new(),
                ..catalogue.clone()
            },
            case: case.clone(),
            conflicted_request,
            frozen: Mutex::new(None),
            timelines: Mutex::new(BTreeSet::new()),
        }
    }

    /// Bind one Timeline to the case's frozen scope.
    pub fn bind_affected_timeline(&self, timeline: TimelineId) {
        self.timelines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(timeline);
    }

    fn affected_timelines(&self) -> Vec<TimelineId> {
        self.timelines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .copied()
            .collect()
    }

    /// Every known Timeline is bound to the frozen scope member for the
    /// request whose access was frozen, and unaffected for every other
    /// request (including that request before its freeze).
    fn observation(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> ErasureVerifiedTopologyObservationV1 {
        let timelines = self.affected_timelines();
        let scope_member = self.catalogue.scope_member.reference();
        let frozen = *self.frozen.lock().unwrap_or_else(PoisonError::into_inner);
        if frozen == Some(request) {
            ErasureVerifiedTopologyObservationV1::new(
                manifest_digest,
                timelines
                    .into_iter()
                    .map(|timeline| (timeline, scope_member))
                    .collect(),
                Vec::new(),
            )
        } else {
            ErasureVerifiedTopologyObservationV1::new(manifest_digest, Vec::new(), timelines)
        }
    }

    fn admission(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeAdmissionV1, ErasureErrorV1> {
        let targets = self
            .case
            .targets
            .iter()
            .map(|target| target.target())
            .collect::<Vec<_>>();
        let policy = self.catalogue.policy.reference();
        let trust = self.catalogue.trust.reference();
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![self.catalogue.scope_member.reference()],
            scope_timeline_ids: self.affected_timelines(),
            target_closure: target_closure_digest(&targets),
            lineage_rule: Some(self.catalogue.lineage_rule.reference()),
        };
        let evidence = requested.provenance.digest().to_vec();
        requested
            .freeze_position
            .ok_or(ErasureErrorV1::ScopeInvalid)
            .and_then(|freeze_position| {
                self.frozen_obligations(request)
                    .map(|(obligations, set)| (freeze_position, obligations, set))
            })
            .and_then(|(freeze_position, obligations, obligation_set)| {
                applicability_matrix(&targets, &obligations)
                    .and_then(|matrix| {
                        ErasureScopeCommitmentV1::new(scope.clone())
                            .map(|commitment| (matrix, commitment.reference()))
                    })
                    .and_then(|(applicability_matrix, scope_commitment)| {
                        freeze_evidence(
                            ErasureFreezeAdmissionEvidenceInputV1 {
                                request,
                                scope_commitment,
                                obligation_set: obligation_set.reference(),
                                applicability_matrix,
                                freeze_position,
                                policy,
                                trust,
                                authorization_provenance: ErasureReferenceV1::from_digest([0; 32]),
                            },
                            evidence,
                        )
                    })
                    .and_then(|(admission, authorization)| {
                        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
                            targets,
                            scope,
                            obligations,
                            obligation_set,
                            freeze_position,
                            freeze_admission_evidence: admission,
                            freeze_authorization_evidence: authorization,
                        })
                    })
            })
    }

    /// The case's obligations for `request` in bytewise order of their
    /// content addresses (the order `EROS1` requires) and their set.
    fn frozen_obligations(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<(Vec<ErasureObligationV1>, ErasureObligationSetV1), ErasureErrorV1> {
        obligations_for(&self.case, request).and_then(|mut obligations| {
            obligations.sort_unstable_by_key(ErasureObligationV1::reference);
            ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
                request,
                obligations: obligations
                    .iter()
                    .map(ErasureObligationV1::reference)
                    .collect(),
                policy: self.catalogue.policy.reference(),
                trust: self.catalogue.trust.reference(),
            })
            .map(|set| (obligations, set))
        })
    }
}

/// One applicability row per `(category, target)`: `Applicable` with its owner
/// when the case lists the obligation, else `Inapplicable` (a legal hold).
fn applicability_matrix(
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
) -> Result<Vec<ErasureFreezeApplicabilityRowV1>, ErasureErrorV1> {
    ErasureInventoryCategoryV1::CANONICAL
        .into_iter()
        .flat_map(|category| {
            targets.iter().zip(0_u64..).map(move |(target, index)| {
                let owner = obligations
                    .iter()
                    .find(|obligation| {
                        obligation.category() == category && obligation.target() == *target
                    })
                    .map(ErasureObligationV1::owner);
                let decision = owner.map_or(ErasureApplicabilityDecisionV1::Inapplicable, |_| {
                    ErasureApplicabilityDecisionV1::Applicable
                });
                ErasureFreezeApplicabilityRowV1::new(category, index, decision, owner)
            })
        })
        .collect()
}

/// The mutually bound freeze-admission body and its authorization evidence.
fn freeze_evidence(
    input: ErasureFreezeAdmissionEvidenceInputV1,
    evidence: Vec<u8>,
) -> Result<
    (
        ErasureFreezeAdmissionEvidenceV1,
        ErasureFreezeAuthorizationEvidenceV1,
    ),
    ErasureErrorV1,
> {
    ErasureFreezeAdmissionEvidenceV1::new(input.clone())
        .and_then(|body| body.authorization_body_digest())
        .and_then(|digest| {
            ErasureFreezeAuthorizationEvidenceV1::new(ErasureFreezeAuthorizationEvidenceInputV1 {
                admission_body_digest: digest,
                policy: input.policy,
                trust: input.trust,
                evidence,
            })
        })
        .and_then(|authorization| {
            ErasureFreezeAdmissionEvidenceV1::new(ErasureFreezeAdmissionEvidenceInputV1 {
                authorization_provenance: authorization.reference(),
                ..input
            })
            .map(|admission| (admission, authorization))
        })
}

impl ErasureFreezeAuthorizationVerifierV1 for FixtureErasureAuthorityV1 {
    fn validate_freeze_authorization(
        &self,
        _admission: &ErasureFreezeAdmissionEvidenceV1,
        _authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for FixtureErasureAuthorityV1 {
    fn validate_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn validate_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl ErasureCoordinatorAuthorityV1 for FixtureErasureAuthorityV1 {
    fn verified_topology_observation(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        Ok(Some(self.observation(request, manifest_digest)))
    }

    fn verified_topology_observation_for_candidate(
        &self,
        request: ErasureReferenceV1,
        manifest_digest: ErasureReferenceV1,
        candidate: &TimelineMeta,
    ) -> Result<Option<ErasureVerifiedTopologyObservationV1>, ErasureErrorV1> {
        self.bind_affected_timeline(candidate.id);
        Ok(Some(self.observation(request, manifest_digest)))
    }

    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        (decision == ErasureAuthorizationDecisionV1::Rejected
            || self.conflicted_request != Some(request))
        .then_some(())
        .ok_or(ErasureErrorV1::PolicyConflict)
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        self.admission(request, requested).map(|admission| {
            *self.frozen.lock().unwrap_or_else(PoisonError::into_inner) = Some(request);
            ErasureAtomicFreezeResultV1::Admitted(Box::new(admission))
        })
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_fork_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
        _input: &ErasureForkAdmissionInputV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn resolve_fork_child_scope(
        &self,
        _parent: TimelineId,
        _child: &TimelineMeta,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        Ok(self.catalogue.scope_member.reference())
    }

    fn resolve_fork_scope_extension(
        &self,
        requirement: ErasureForkScopeRequirementV1,
        input: &ErasureForkAdmissionInputV1,
    ) -> Result<ErasureScopeExtensionV1, ErasureErrorV1> {
        ErasureScopeExtensionV1::new(ErasureScopeExtensionInputV1 {
            request: requirement.request(),
            scope_commitment: requirement.scope_commitment(),
            fork: input.child_scope,
            child_timeline: input.child.id,
            lineage_rule: requirement.lineage_rule(),
            predecessor_extension: requirement.predecessor_extension(),
            admission_provenance: input.operation,
        })
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            self.catalogue.quota_reservation.reference(),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

/// Authenticates exactly the catalogue's rejoin attestation.
struct FixtureRejoinVerifierV1(ErasureReferenceV1);

impl ErasureRejoinAttestationVerifierV1 for FixtureRejoinVerifierV1 {
    fn verify(&self, proof: &ErasureRejoinProofV1) -> Result<(), ErasureErrorV1> {
        (proof.attestation() == self.0)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }
}

/// The logical positions `(admitted, deadline, issue)` of one attempt: the
/// first attempt ends at the `ERQ1` horizon (20), each retry ten positions
/// later.
const fn attempt_positions(ordinal: u64) -> (u64, u64, u64) {
    let deadline = 20 + 10 * ordinal;
    (deadline - 9, deadline, deadline)
}

fn previous_claim(
    previous: Option<&ErasureReceiptV1>,
    obligation: &ErasureObligationV1,
) -> ErasureReplayClaimV1 {
    previous
        .and_then(|receipt| {
            let inventories = receipt.inventories();
            [
                &inventories.artifacts,
                &inventories.keys,
                &inventories.replicas,
                &inventories.backups,
            ]
            .into_iter()
            .flatten()
            .find(|row| row.category == obligation.category() && row.target == obligation.target())
            .map(|row| row.transition.to)
        })
        .unwrap_or(ErasureReplayClaimV1::Exact)
}

fn inventory_row(
    row: &ErasureCaseRowV1,
    obligation: &ErasureObligationV1,
    previous: Option<&ErasureReceiptV1>,
) -> Result<ErasureInventoryResultV1, ErasureCaseErrorV1> {
    let from = previous_claim(previous, obligation);
    let target = obligation.target();
    ReplayClaimEvaluatorV1::evaluate(
        from,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                target.artifact_class,
                target.artifact_digest,
                ArtifactDataClassV1::PrivateSubjectData,
                None,
                obligation.owner(),
                ArtifactOptionalityV1::Required,
                row.rule.rule(),
            ),
            current_claim: from,
            state: row.state.state(),
        }],
    )
    .map(|evaluation| ErasureInventoryResultV1 {
        category: obligation.category(),
        target,
        transition: ErasureArtifactTransitionV1 {
            from,
            to: evaluation.replay_claim(),
            reason: row.reason.reference(),
            owner: obligation.owner(),
            acknowledgements: row.acknowledgements.reference(),
            provenance: row.provenance.reference(),
        },
        retained_disclosure: row.retained_disclosure.reference(),
    })
    .map_err(ErasureCaseErrorV1::Fixture)
}

fn rows_of(
    rows: &[ErasureInventoryResultV1],
    category: ErasureInventoryCategoryV1,
) -> Vec<ErasureInventoryResultV1> {
    rows.iter()
        .filter(|row| row.category == category)
        .copied()
        .collect()
}

/// The receipt input of one attempt. The coordinator derives every identity,
/// lifecycle, acknowledgement and owner field from durable evidence; the case
/// supplies the inventories, the issue position and the signature commitment.
fn receipt_input(
    rows: &[ErasureInventoryResultV1],
    issue_position: u64,
    signature: ErasureReferenceV1,
) -> ErasureReceiptInputV1 {
    let zero = ErasureReferenceV1::from_digest([0; 32]);
    ErasureReceiptInputV1 {
        request: zero,
        terminal_state: zero,
        coordinator: zero,
        lifecycle: ErasureLifecycleV1::Complete,
        freeze_position: 0,
        acknowledgements: Vec::new(),
        frozen_targets: Vec::new(),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        inventories: ErasureReceiptInventoriesV1 {
            artifacts: rows_of(rows, ErasureInventoryCategoryV1::Artifact),
            keys: rows_of(rows, ErasureInventoryCategoryV1::Key),
            replicas: rows_of(rows, ErasureInventoryCategoryV1::Replica),
            backups: rows_of(rows, ErasureInventoryCategoryV1::Backup),
        },
        replay_claim: ErasureReplayClaimV1::Exact,
        policy: zero,
        trust: zero,
        provenance: zero,
        issue_position,
        signature,
        receipt_digest: zero,
    }
}

fn read_request(root: &Path, path: &str) -> Result<ErasureRequestV1, ErasureCaseErrorV1> {
    std::fs::read(root.join(path))
        .map_err(ErasureCaseErrorV1::from)
        .and_then(|bytes| {
            ErasureRequestV1::from_canonical_cbor(&bytes).map_err(ErasureCaseErrorV1::Fixture)
        })
}

/// One case's authority and host.
pub struct ErasureCaseRunV1 {
    catalogue: ErasureCaseCatalogueV1,
    case: ErasureCaseV1,
    authority: Arc<FixtureErasureAuthorityV1>,
    host: ErasureExecutionHostV1,
}

impl ErasureCaseRunV1 {
    /// Open the public host of `case` over `store`.
    ///
    /// `conflicted_request` is the request whose authorization the authority
    /// refuses with `PolicyConflict` (the original request of a
    /// policy-conflict case).
    ///
    /// # Errors
    /// Returns a closed fixture or host error.
    pub fn open(
        catalogue: &ErasureCaseCatalogueV1,
        case: &ErasureCaseV1,
        store: StoreConfig,
        conflicted_request: Option<ErasureReferenceV1>,
    ) -> Result<Self, ErasureCaseErrorV1> {
        let authority = Arc::new(FixtureErasureAuthorityV1::new(
            catalogue,
            case,
            conflicted_request,
        ));
        let plugin: Arc<dyn ErasureCoordinatorAuthorityV1> = authority.clone();
        ErasureCoordinatorCompositionV1::new(plugin, catalogue.coordinator.reference())
            .map_err(ErasureCaseErrorV1::Fixture)
            .and_then(|composition| {
                ErasureExecutionHostV1::open_with_authority(
                    store,
                    &composition,
                    ErasureRecoveryLimitsV1::compiled_maximum(),
                )
                .map_err(ErasureCaseErrorV1::Host)
            })
            .map(|host| Self {
                catalogue: catalogue.clone(),
                case: case.clone(),
                authority,
                host,
            })
    }

    /// The public host, for commands and reads outside the case script.
    pub const fn host(&mut self) -> &mut ErasureExecutionHostV1 {
        &mut self.host
    }

    /// The case's coordinator authority.
    #[must_use]
    pub fn authority(&self) -> &FixtureErasureAuthorityV1 {
        &self.authority
    }

    /// Run the case script and return every record it produced.
    ///
    /// `fixture_root` is the erasure fixture directory the request files are
    /// read from.
    ///
    /// # Errors
    /// Returns a closed read, fixture or host error, or
    /// [`ErasureCaseErrorV1::MissingHistory`].
    pub fn execute(
        &mut self,
        fixture_root: &Path,
    ) -> Result<ErasureCaseRecordV1, ErasureCaseErrorV1> {
        let case = self.case.clone();
        read_request(fixture_root, &case.request)
            .and_then(|request| match &case.policy_conflict {
                None => self.submit(request).map(|request| (Vec::new(), request)),
                Some(conflict) => self
                    .reject_and_correct(fixture_root, request, conflict)
                    .map(|(rejected, corrected)| (vec![rejected], corrected)),
            })
            .and_then(|(mut histories, request)| {
                self.complete(request).map(|history| {
                    histories.push(history);
                    histories
                })
            })
            .and_then(|histories| {
                self.rejoin(&histories)
                    .map(|rejoins| ErasureCaseRecordV1 { histories, rejoins })
            })
    }

    fn submit(
        &mut self,
        request: ErasureRequestV1,
    ) -> Result<ErasureRequestV1, ErasureCaseErrorV1> {
        self.host
            .command_sender()
            .and_then(|mut commands| {
                commands.submit_erasure_request(request.clone(), request.provenance())
            })
            .map(|_| request)
            .map_err(ErasureCaseErrorV1::Host)
    }

    fn reject_and_correct(
        &mut self,
        fixture_root: &Path,
        original: ErasureRequestV1,
        conflict: &ErasureCasePolicyConflictV1,
    ) -> Result<(ErasureCaseHistoryV1, ErasureRequestV1), ErasureCaseErrorV1> {
        let reference = original.reference();
        let authorization = self.case.authorization_provenance.reference();
        let rejection = conflict.rejection_provenance.reference();
        self.host
            .command_sender()
            .and_then(|mut commands| {
                commands
                    .submit_erasure_request(original.clone(), original.provenance())
                    .map(|_| {
                        commands
                            .authorize_erasure_request(reference, authorization)
                            .err()
                    })
                    .and_then(|refusal| {
                        commands
                            .reject_erasure_request(reference, rejection)
                            .map(|rejected| (refusal, rejected))
                    })
            })
            .map_err(ErasureCaseErrorV1::Host)
            .and_then(|(refusal, rejected)| {
                ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
                    rejected_request: reference,
                    rejected_terminal_state: rejected.state_digest(),
                    correction_reason: conflict.correction_reason.reference(),
                    authorization_provenance: conflict.correction_authorization.reference(),
                })
                .map_err(ErasureCaseErrorV1::Fixture)
                .and_then(|correction| {
                    read_request(fixture_root, &conflict.request).and_then(|corrected| {
                        self.host
                            .command_sender()
                            .and_then(|mut commands| {
                                commands
                                    .submit_corrected_erasure_request(corrected.clone(), correction)
                            })
                            .map_err(ErasureCaseErrorV1::Host)
                            .and_then(|_| self.history(original, refusal, Vec::new()))
                            .map(|history| (history, corrected))
                    })
                })
            })
    }

    fn history(
        &mut self,
        request: ErasureRequestV1,
        authorization_refusal: Option<ErasureHostErrorV1>,
        receipts: Vec<ErasureReceiptV1>,
    ) -> Result<ErasureCaseHistoryV1, ErasureCaseErrorV1> {
        self.host
            .read_sender()
            .and_then(|mut reads| reads.erasure_state_history(request.reference()))
            .map_err(ErasureCaseErrorV1::Host)
            .and_then(|history| history.ok_or(ErasureCaseErrorV1::MissingHistory))
            .map(|mut states| {
                states.reverse();
                ErasureCaseHistoryV1 {
                    authorization_refusal,
                    request,
                    states,
                    receipts,
                }
            })
    }

    fn complete(
        &mut self,
        request: ErasureRequestV1,
    ) -> Result<ErasureCaseHistoryV1, ErasureCaseErrorV1> {
        let reference = request.reference();
        let freeze = ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::AccessFrozen,
            freeze_position: Some(10),
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            provenance: self.case.freeze_provenance.reference(),
        };
        let authorization = self.case.authorization_provenance.reference();
        let attempts = self.case.attempts.clone();
        self.host
            .command_sender()
            .and_then(|mut commands| {
                commands
                    .authorize_erasure_request(reference, authorization)
                    .and_then(|_| commands.freeze_access(reference, &freeze))
            })
            .map_err(ErasureCaseErrorV1::Host)
            .and_then(|_| case_obligations(&self.case, reference))
            .and_then(|obligations| {
                attempts.iter().zip(0_u64..).try_fold(
                    Vec::new(),
                    |mut receipts: Vec<ErasureReceiptV1>, (attempt, ordinal)| {
                        self.attempt(reference, &obligations, attempt, ordinal, receipts.last())
                            .map(|receipt| {
                                receipts.push(receipt);
                                receipts
                            })
                    },
                )
            })
            .and_then(|receipts| self.history(request, None, receipts))
    }

    fn attempt(
        &mut self,
        request: ErasureReferenceV1,
        obligations: &[ErasureObligationV1],
        attempt: &ErasureCaseAttemptV1,
        ordinal: u64,
        previous: Option<&ErasureReceiptV1>,
    ) -> Result<ErasureReceiptV1, ErasureCaseErrorV1> {
        let resolved = previous.map_or_else(Vec::new, |receipt| {
            receipt
                .acknowledgements()
                .iter()
                .filter(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged)
                .map(|ack| ack.obligation)
                .collect()
        });
        let unresolved = obligations
            .iter()
            .filter(|obligation| !resolved.contains(&obligation.reference()))
            .copied()
            .collect::<Vec<_>>();
        let (admitted_position, deadline_position, issue_position) = attempt_positions(ordinal);
        let signature = attempt.signature.reference();
        ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request,
            attempt_ordinal: ordinal,
            source_receipt: previous.map(ErasureReceiptV1::receipt_digest),
            unresolved_obligations: unresolved
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            command_identities: unresolved
                .iter()
                .map(ErasureObligationV1::command_identity)
                .collect(),
            policy: self.catalogue.policy.reference(),
            trust: self.catalogue.trust.reference(),
            admitted_position,
            deadline_position,
            authorization_provenance: attempt.authorization_provenance.reference(),
        })
        .map_err(ErasureCaseErrorV1::Fixture)
        .and_then(|admission| {
            acknowledgements(obligations, attempt).and_then(|acknowledgements| {
                attempt
                    .rows
                    .iter()
                    .map(|row| {
                        obligations
                            .get(row.obligation)
                            .ok_or(ErasureCaseErrorV1::InvalidIndex)
                            .and_then(|obligation| inventory_row(row, obligation, previous))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .and_then(|rows| {
                        let input = receipt_input(&rows, issue_position, signature);
                        self.host
                            .command_sender()
                            .and_then(|mut commands| {
                                commands
                                    .dispatch_erasure_destruction(request, &admission)
                                    .and_then(|_| {
                                        acknowledgements.iter().try_for_each(|acknowledgement| {
                                            commands
                                                .acknowledge_erasure(request, *acknowledgement)
                                                .map(|_| ())
                                        })
                                    })
                                    .and_then(|()| {
                                        commands.finalize_erasure_request(request, &input)
                                    })
                            })
                            .map_err(ErasureCaseErrorV1::Host)
                    })
            })
        })
    }

    fn rejoin(
        &self,
        histories: &[ErasureCaseHistoryV1],
    ) -> Result<Vec<ErasureCaseRejoinRecordV1>, ErasureCaseErrorV1> {
        let verifier = FixtureRejoinVerifierV1(self.catalogue.rejoin_attestation.reference());
        histories
            .last()
            .ok_or(ErasureCaseErrorV1::MissingHistory)
            .and_then(|history| {
                let request = history.request.reference();
                case_obligations(&self.case, request).and_then(|obligations| {
                    self.case
                        .rejoins
                        .iter()
                        .map(|rejoin| {
                            rejoin_record(&self.case, history, &obligations, rejoin, &verifier)
                        })
                        .collect()
                })
            })
    }
}

/// The owner acknowledgements of one attempt, in arrival order.
fn acknowledgements(
    obligations: &[ErasureObligationV1],
    attempt: &ErasureCaseAttemptV1,
) -> Result<Vec<ErasureAcknowledgementV1>, ErasureCaseErrorV1> {
    attempt
        .acknowledgements
        .iter()
        .map(|ack| {
            obligations
                .get(ack.obligation)
                .ok_or(ErasureCaseErrorV1::InvalidIndex)
                .map(|obligation| ErasureAcknowledgementV1 {
                    obligation: obligation.reference(),
                    target: obligation.target(),
                    owner: obligation.owner(),
                    evidence: ack.evidence.reference(),
                    outcome: ack.outcome.outcome(),
                })
        })
        .collect()
}

/// Build one `ERRJ1` proof for the case's replica and admit it against its
/// receipt.
fn rejoin_record(
    case: &ErasureCaseV1,
    history: &ErasureCaseHistoryV1,
    obligations: &[ErasureObligationV1],
    rejoin: &ErasureCaseRejoinV1,
    verifier: &FixtureRejoinVerifierV1,
) -> Result<ErasureCaseRejoinRecordV1, ErasureCaseErrorV1> {
    history
        .receipts
        .get(rejoin.attempt)
        .zip(case.targets.first())
        .ok_or(ErasureCaseErrorV1::InvalidIndex)
        .and_then(|(receipt, replica)| {
            rejoin
                .entries
                .iter()
                .map(|entry| {
                    obligations
                        .get(entry.obligation)
                        .ok_or(ErasureCaseErrorV1::InvalidIndex)
                        .map(|obligation| ErasureRejoinInventoryV1 {
                            category: obligation.category(),
                            target: obligation.target(),
                            owner: obligation.owner(),
                            disposition: entry.disposition.disposition(),
                            evidence: entry.evidence.reference(),
                        })
                })
                .collect::<Result<Vec<_>, _>>()
                .and_then(|entries| {
                    ErasureRejoinProofV1::new(ErasureRejoinProofInputV1 {
                        request: history.request.reference(),
                        terminal_receipt: receipt.receipt_digest(),
                        replica_set: replica.replica_set.reference(),
                        replica_id: replica.replica_id.reference(),
                        inventory_generation: rejoin.inventory_generation.reference(),
                        entries,
                        attestation: rejoin.attestation.reference(),
                    })
                    .map(|proof| ErasureCaseRejoinRecordV1 {
                        outcome: proof.admit(receipt, verifier),
                        proof,
                    })
                    .map_err(ErasureCaseErrorV1::Fixture)
                })
        })
}
