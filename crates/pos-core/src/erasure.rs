//! ADR-060's payload-free ERQ1, ERS1, and ERC1 public contracts.
//!
//! This module deliberately excludes storage, key destruction, artifact work,
//! backup inventory, and replay evaluation. Those operations belong to the
//! adapters and follow-up tickets named by ADR-060.

use std::cmp::Ordering;

const VERSION: u64 = 1;
const ERQ1: &str = "ERQ1";
const ERS1: &str = "ERS1";
const ERC1: &str = "ERC1";

/// Largest encoded ERQ1 or ERS1 accepted by V1.
pub const ERASURE_REQUEST_OR_STATE_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded ERC1 accepted by V1.
pub const ERASURE_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest selector or owner collection accepted by V1.
pub const ERASURE_MAX_REFERENCES: usize = 4_096;
/// Largest number of entries in each ERC1 inventory.
pub const ERASURE_MAX_INVENTORY_RESULTS: usize = 65_536;

/// Closed, payload-safe failures exposed by ERQ1, ERS1, and ERC1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureErrorV1 {
    /// Malformed CBOR or closed enum value.
    InvalidEncoding,
    /// Unsupported wire version.
    UnsupportedVersion,
    /// Requester is not authorized.
    Unauthorized,
    /// Scope, selector, or owner evidence is invalid.
    ScopeInvalid,
    /// Lifecycle or policy evidence conflicts.
    PolicyConflict,
    /// Access could not be frozen.
    AccessFreezeFailed,
    /// Key registry is unavailable.
    KeyRegistryUnavailable,
    /// Eligible key destruction failed.
    KeyDestructionFailed,
    /// Eligible artifact deletion or redaction failed.
    ArtifactDeletionFailed,
    /// Replica acknowledgement timed out.
    ReplicaTimeout,
    /// Replica negatively acknowledged.
    ReplicaNegativeAcknowledgement,
    /// Backup inventory proof is incomplete.
    BackupInventoryIncomplete,
    /// Backup deletion remains pending.
    BackupDeletionPending,
    /// Receipt commit failed.
    ReceiptCommitFailed,
    /// Trust snapshot is invalid.
    TrustSnapshotInvalid,
    /// Provenance is missing or invalid.
    ProvenanceMissing,
}
impl ErasureErrorV1 {
    /// Return the stable V1 error code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::InvalidEncoding => 0,
            Self::UnsupportedVersion => 1,
            Self::Unauthorized => 2,
            Self::ScopeInvalid => 3,
            Self::PolicyConflict => 4,
            Self::AccessFreezeFailed => 5,
            Self::KeyRegistryUnavailable => 6,
            Self::KeyDestructionFailed => 7,
            Self::ArtifactDeletionFailed => 8,
            Self::ReplicaTimeout => 9,
            Self::ReplicaNegativeAcknowledgement => 10,
            Self::BackupInventoryIncomplete => 11,
            Self::BackupDeletionPending => 12,
            Self::ReceiptCommitFailed => 13,
            Self::TrustSnapshotInvalid => 14,
            Self::ProvenanceMissing => 15,
        }
    }

    /// Decode one stable V1 error code.
    ///
    /// # Errors
    ///
    /// Returns [`Self::InvalidEncoding`] for an unknown code.
    pub const fn from_code(code: u64) -> Result<Self, Self> {
        match code {
            0 => Ok(Self::InvalidEncoding),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::ScopeInvalid),
            4 => Ok(Self::PolicyConflict),
            5 => Ok(Self::AccessFreezeFailed),
            6 => Ok(Self::KeyRegistryUnavailable),
            7 => Ok(Self::KeyDestructionFailed),
            8 => Ok(Self::ArtifactDeletionFailed),
            9 => Ok(Self::ReplicaTimeout),
            10 => Ok(Self::ReplicaNegativeAcknowledgement),
            11 => Ok(Self::BackupInventoryIncomplete),
            12 => Ok(Self::BackupDeletionPending),
            13 => Ok(Self::ReceiptCommitFailed),
            14 => Ok(Self::TrustSnapshotInvalid),
            15 => Ok(Self::ProvenanceMissing),
            _ => Err(Self::InvalidEncoding),
        }
    }
}

impl std::fmt::Display for ErasureErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "erasure contract error {}", self.code())
    }
}

impl std::error::Error for ErasureErrorV1 {}

/// A minimized digest reference; it never carries erased payload bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErasureReferenceV1([u8; 32]);

impl ErasureReferenceV1 {
    /// Build a reference from an already minimized digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the digest for deterministic wire encoding.
    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// The data class authorized for an erasure request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureScopeV1 {
    /// Private subject data.
    PrivateSubjectData,
    /// Consented shared data.
    ConsentedSharedData,
    /// Public record.
    PublicRecord,
    /// Aggregate data.
    Aggregate,
    /// Minimized structural audit metadata.
    StructuralAuditMetadata,
}

impl ErasureScopeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::PrivateSubjectData => 0,
            Self::ConsentedSharedData => 1,
            Self::PublicRecord => 2,
            Self::Aggregate => 3,
            Self::StructuralAuditMetadata => 4,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::PrivateSubjectData),
            1 => Ok(Self::ConsentedSharedData),
            2 => Ok(Self::PublicRecord),
            3 => Ok(Self::Aggregate),
            4 => Ok(Self::StructuralAuditMetadata),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// The ADR-060 lifecycle. No edge is backward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureLifecycleV1 {
    /// Request recorded.
    Submitted,
    /// Scope authorized.
    Authorized,
    /// Future access frozen at a Tick Boundary.
    AccessFrozen,
    /// Idempotent destruction commands dispatched.
    DestructionDispatched,
    /// Owner acknowledgements pending.
    AwaitingAcknowledgements,
    /// All required acknowledgements are positive.
    Complete,
    /// Required acknowledgement is missing, stale, or negative.
    PartialFailure,
    /// Rejected before access freeze.
    Rejected,
}

impl ErasureLifecycleV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Submitted => 0,
            Self::Authorized => 1,
            Self::AccessFrozen => 2,
            Self::DestructionDispatched => 3,
            Self::AwaitingAcknowledgements => 4,
            Self::Complete => 5,
            Self::PartialFailure => 6,
            Self::Rejected => 7,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Submitted),
            1 => Ok(Self::Authorized),
            2 => Ok(Self::AccessFrozen),
            3 => Ok(Self::DestructionDispatched),
            4 => Ok(Self::AwaitingAcknowledgements),
            5 => Ok(Self::Complete),
            6 => Ok(Self::PartialFailure),
            7 => Ok(Self::Rejected),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
    /// Report whether `next` is the single permitted forward edge.
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        match self {
            Self::Submitted => matches!(next, Self::Authorized | Self::Rejected),
            Self::Authorized => matches!(next, Self::AccessFrozen),
            Self::AccessFrozen => matches!(next, Self::DestructionDispatched),
            Self::DestructionDispatched => matches!(next, Self::AwaitingAcknowledgements),
            Self::AwaitingAcknowledgements => matches!(next, Self::Complete | Self::PartialFailure),
            Self::Complete | Self::PartialFailure | Self::Rejected => false,
        }
    }
    /// Report whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::PartialFailure | Self::Rejected)
    }
}

/// Complete structural ERQ1 construction input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRequestInputV1 {
    /// Stable request digest.
    pub request: ErasureReferenceV1,
    /// Minimized subject digest.
    pub subject: ErasureReferenceV1,
    /// Authorized class.
    pub scope: ErasureScopeV1,
    /// Eligible digest selectors.
    pub selectors: Vec<ErasureReferenceV1>,
    /// Requester, authorization, policy, and provenance digests.
    pub requester: ErasureReferenceV1,
    /// Authorization evidence digest.
    pub authorization: ErasureReferenceV1,
    /// Policy version digest.
    pub policy: ErasureReferenceV1,
    /// Request and scope-horizon positions.
    pub request_position: u64,
    /// Last position included by the scope.
    pub horizon_position: u64,
    /// Provenance digest.
    pub provenance: ErasureReferenceV1,
}

/// A validated ERQ1 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRequestV1(ErasureRequestInputV1);

impl ErasureRequestV1 {
    /// Validate ERQ1 and normalize selector ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ScopeInvalid`] for empty, duplicate,
    /// oversized, or impossible scope evidence.
    pub fn new(mut input: ErasureRequestInputV1) -> Result<Self, ErasureErrorV1> {
        if input.selectors.is_empty()
            || input.selectors.len() > ERASURE_MAX_REFERENCES
            || input.request_position > input.horizon_position
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.selectors.sort_unstable();
        if has_duplicate(&input.selectors) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self(input))
    }
    /// Return the request digest used by ERS1 and ERC1.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.0.request
    }
    /// Return the request provenance bound into ERQ1.
    #[must_use]
    pub const fn provenance(&self) -> ErasureReferenceV1 {
        self.0.provenance
    }
    /// Encode the exact-length deterministic ERQ1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if canonical serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_canonical(&request_value(&self.0))
    }
    /// Decode ERQ1 without normalizing received evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, unsupported, or invalid scope evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_REQUEST_OR_STATE_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 12).and_then(request_from_fields))
    }
}

/// The replay claim supported by remaining evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureReplayClaimV1 {
    /// Exact evidence remains.
    Exact,
    /// Authoritative data remains but views are redacted.
    ExactAuthoritativeWithRedactedViews,
    /// Only structural evidence remains.
    StructuralOnly,
    /// Required artifact is unavailable.
    UnverifiableArtifactsMissing,
    /// Profile incompatibility, orthogonal to erasure.
    IncompatibleProfile,
}

impl ErasureReplayClaimV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Exact => 0,
            Self::ExactAuthoritativeWithRedactedViews => 1,
            Self::StructuralOnly => 2,
            Self::UnverifiableArtifactsMissing => 3,
            Self::IncompatibleProfile => 4,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Exact),
            1 => Ok(Self::ExactAuthoritativeWithRedactedViews),
            2 => Ok(Self::StructuralOnly),
            3 => Ok(Self::UnverifiableArtifactsMissing),
            4 => Ok(Self::IncompatibleProfile),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
    const fn rank(self) -> u64 {
        match self {
            Self::Exact => 0,
            Self::ExactAuthoritativeWithRedactedViews => 1,
            Self::StructuralOnly => 2,
            Self::UnverifiableArtifactsMissing => 3,
            Self::IncompatibleProfile => 4,
        }
    }
    const fn preserves_or_weakens(self, next: Self) -> bool {
        self.rank() <= next.rank()
    }
}

/// Closed artifact classes recorded by ERC1 without carrying artifact bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ErasureArtifactClassV1 {
    /// Timeline or replay evidence.
    TimelineReplay,
    /// Reproducibility manifest.
    ReproManifest,
    /// Causal trace evidence.
    CausalTrace,
    /// Calibration report.
    CalibrationReport,
    /// Exported artifact.
    Export,
    /// Fork, snapshot, or counterfactual artifact.
    ForkOrSnapshot,
    /// Conformance evidence.
    ConformanceReport,
}

impl ErasureArtifactClassV1 {
    const fn code(self) -> u64 {
        match self {
            Self::TimelineReplay => 0,
            Self::ReproManifest => 1,
            Self::CausalTrace => 2,
            Self::CalibrationReport => 3,
            Self::Export => 4,
            Self::ForkOrSnapshot => 5,
            Self::ConformanceReport => 6,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::TimelineReplay),
            1 => Ok(Self::ReproManifest),
            2 => Ok(Self::CausalTrace),
            3 => Ok(Self::CalibrationReport),
            4 => Ok(Self::Export),
            5 => Ok(Self::ForkOrSnapshot),
            6 => Ok(Self::ConformanceReport),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// Closed role of a key recorded by ERC1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ErasureKeyRoleV1 {
    /// Data-encryption key.
    DataEncryption,
    /// Signing key, distinct from data encryption.
    Signing,
    /// Backup envelope key.
    BackupEnvelope,
    /// Replica transport key.
    ReplicaTransport,
}

impl ErasureKeyRoleV1 {
    const fn code(self) -> u64 {
        match self {
            Self::DataEncryption => 0,
            Self::Signing => 1,
            Self::BackupEnvelope => 2,
            Self::ReplicaTransport => 3,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::DataEncryption),
            1 => Ok(Self::Signing),
            2 => Ok(Self::BackupEnvelope),
            3 => Ok(Self::ReplicaTransport),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// One authorized target in the fixed ADR-060 canonical order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErasureRequiredTargetV1 {
    /// Artifact class.
    pub artifact_class: ErasureArtifactClassV1,
    /// Artifact identity digest.
    pub artifact_digest: ErasureReferenceV1,
    /// Key role.
    pub key_role: ErasureKeyRoleV1,
    /// Key identity digest.
    pub key_digest: ErasureReferenceV1,
    /// Registered replica-set digest.
    pub replica_set: ErasureReferenceV1,
    /// Registered replica identity digest.
    pub replica_id: ErasureReferenceV1,
}

/// Per-artifact replay-claim transition, disclosed only by digests and closed enums.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureArtifactTransitionV1 {
    /// Replay claim before erasure.
    pub from: ErasureReplayClaimV1,
    /// Replay claim after erasure.
    pub to: ErasureReplayClaimV1,
    /// Fixed reason/evidence digest for the transition.
    pub reason: ErasureReferenceV1,
    /// Registered owner digest.
    pub owner: ErasureReferenceV1,
    /// Acknowledgement commitment digest.
    pub acknowledgements: ErasureReferenceV1,
    /// Transition provenance digest.
    pub provenance: ErasureReferenceV1,
}

/// One payload-free ERC1 inventory result.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ErasureInventoryCategoryV1 {
    /// Evidence from the registered artifact owner.
    Artifact,
    /// Evidence from the authoritative key registry.
    Key,
    /// Evidence from a replica-local owner.
    Replica,
    /// Evidence from the backup inventory owner.
    Backup,
}

impl ErasureInventoryCategoryV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Artifact => 0,
            Self::Key => 1,
            Self::Replica => 2,
            Self::Backup => 3,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Artifact),
            1 => Ok(Self::Key),
            2 => Ok(Self::Replica),
            3 => Ok(Self::Backup),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// One payload-free ERC1 inventory result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureInventoryResultV1 {
    /// The owner category represented by the containing inventory.
    pub category: ErasureInventoryCategoryV1,
    /// Target ordered by the ADR-060 tuple.
    pub target: ErasureRequiredTargetV1,
    /// Per-artifact degradation transition.
    pub transition: ErasureArtifactTransitionV1,
    /// Digest of the retained disclosure, never its payload.
    pub retained_disclosure: ErasureReferenceV1,
}

impl Ord for ErasureInventoryResultV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.target.cmp(&other.target)
    }
}
impl PartialOrd for ErasureInventoryResultV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The four independently bounded ERC1 inventories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureReceiptInventoriesV1 {
    /// Artifact-owner outcomes.
    pub artifacts: Vec<ErasureInventoryResultV1>,
    /// Key-registry outcomes.
    pub keys: Vec<ErasureInventoryResultV1>,
    /// Replica-local outcomes.
    pub replicas: Vec<ErasureInventoryResultV1>,
    /// Backup-inventory outcomes.
    pub backups: Vec<ErasureInventoryResultV1>,
}

/// Evidence supplied with one ERS1 transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureStateTransitionV1 {
    /// Requested next lifecycle state.
    pub lifecycle: ErasureLifecycleV1,
    /// Tick Boundary position, immutable after freeze.
    pub freeze_position: Option<u64>,
    /// Owners without a positive acknowledgement.
    pub pending_owners: Vec<ErasureReferenceV1>,
    /// Owners with stale or negative acknowledgement.
    pub failed_owners: Vec<ErasureReferenceV1>,
    /// Positive acknowledgements proving the frozen closure for `Complete`.
    /// This evidence is consumed by the core coordinator; it is not caller
    /// permission to skip host dispatch or durable commit.
    pub acknowledged_targets: Vec<ErasureRequiredTargetV1>,
    /// Evidence-derived replay claim.
    pub replay_claim: ErasureReplayClaimV1,
    /// Transition provenance digest.
    pub provenance: ErasureReferenceV1,
}

/// Digest-linked, monotonic ERS1 state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureStateV1 {
    request: ErasureReferenceV1,
    lifecycle: ErasureLifecycleV1,
    freeze_position: Option<u64>,
    coordinator: ErasureReferenceV1,
    pending_owners: Vec<ErasureReferenceV1>,
    failed_owners: Vec<ErasureReferenceV1>,
    replay_claim: ErasureReplayClaimV1,
    previous_state: Option<ErasureReferenceV1>,
    provenance: ErasureReferenceV1,
    state_digest: ErasureReferenceV1,
}

impl ErasureStateV1 {
    /// Create the initial submitted ERS1 state.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if its digest cannot be derived.
    pub fn submitted(
        request: ErasureReferenceV1,
        coordinator: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        Self {
            request,
            lifecycle: ErasureLifecycleV1::Submitted,
            freeze_position: None,
            coordinator,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            previous_state: None,
            provenance,
            state_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the current lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.lifecycle
    }
    /// Return the predecessor-link digest for the next state.
    #[must_use]
    pub const fn state_digest(&self) -> ErasureReferenceV1 {
        self.state_digest
    }
    /// Return the ERQ1 request digest bound to this state.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.request
    }
    /// Return the coordinator identity which authored this state.
    #[must_use]
    pub const fn coordinator(&self) -> ErasureReferenceV1 {
        self.coordinator
    }
    /// Return the provenance committed for this state transition.
    #[must_use]
    pub const fn provenance(&self) -> ErasureReferenceV1 {
        self.provenance
    }
    /// Return the frozen Tick Boundary, if access has been frozen.
    #[must_use]
    pub const fn freeze_position(&self) -> Option<u64> {
        self.freeze_position
    }
    /// Return the evidence-derived replay claim.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.replay_claim
    }
    /// Return the preceding ERS1 digest, if this is not the root state.
    #[must_use]
    pub const fn previous_state(&self) -> Option<ErasureReferenceV1> {
        self.previous_state
    }
    /// Return owners whose required target has not positively acknowledged.
    #[must_use]
    pub fn pending_owners(&self) -> &[ErasureReferenceV1] {
        &self.pending_owners
    }
    /// Return owners whose acknowledgement is stale or negative.
    #[must_use]
    pub fn failed_owners(&self) -> &[ErasureReferenceV1] {
        &self.failed_owners
    }
    /// Advance exactly one permitted edge while preserving the freeze position.
    ///
    /// # Errors
    ///
    /// Returns a closed error for a backward edge, changed freeze position,
    /// invalid owner evidence, or invalid terminal evidence.
    pub(crate) fn transition(
        &self,
        mut change: ErasureStateTransitionV1,
    ) -> Result<Self, ErasureErrorV1> {
        if !self.lifecycle.permits(change.lifecycle)
            || !freeze_is_monotonic(self.freeze_position, change.freeze_position)
            || !self.replay_claim.preserves_or_weakens(change.replay_claim)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if change.lifecycle == ErasureLifecycleV1::Complete
            && change.acknowledged_targets.is_empty()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        change.pending_owners.sort_unstable();
        change.failed_owners.sort_unstable();
        if invalid_owner_sets(&change.pending_owners, &change.failed_owners) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            request: self.request,
            lifecycle: change.lifecycle,
            freeze_position: change.freeze_position,
            coordinator: self.coordinator,
            pending_owners: change.pending_owners,
            failed_owners: change.failed_owners,
            replay_claim: change.replay_claim,
            previous_state: Some(self.state_digest),
            provenance: change.provenance,
            state_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Encode exact-length deterministic ERS1.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid evidence or a mismatched state digest.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate()
            .and_then(|()| self.clone().with_digest())
            .and_then(|expected| encode_canonical(&state_value(&expected)))
    }
    /// Decode ERS1 without accepting invented history.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed state, invalid evidence, or digest mismatch.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_REQUEST_OR_STATE_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 12).and_then(state_from_fields))
    }
    fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        self.validate()
            .and_then(|()| encode_canonical(&state_core_value(&self)))
            .map(|bytes| {
                self.state_digest = ErasureReferenceV1::from_digest(domain_digest(ERS1, &bytes));
                self
            })
    }
    fn validate(&self) -> Result<(), ErasureErrorV1> {
        if matches!(
            self.lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::Rejected
        ) && (!self.pending_owners.is_empty() || !self.failed_owners.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let needs_freeze = matches!(
            self.lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        );
        if needs_freeze != self.freeze_position.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if (self.lifecycle != ErasureLifecycleV1::Submitted) != self.previous_state.is_some() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.lifecycle == ErasureLifecycleV1::Complete
            && (!self.pending_owners.is_empty() || !self.failed_owners.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.lifecycle == ErasureLifecycleV1::PartialFailure
            && self.pending_owners.is_empty()
            && self.failed_owners.is_empty()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }
}

/// One owner acknowledgement, containing only structural digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAcknowledgementV1 {
    /// Authorized target this acknowledgement closes.
    pub target: ErasureRequiredTargetV1,
    /// Registered owner digest.
    pub owner: ErasureReferenceV1,
    /// Command or artifact evidence digest.
    pub evidence: ErasureReferenceV1,
    /// Local outcome.
    pub outcome: ErasureAcknowledgementOutcomeV1,
}

impl Ord for ErasureAcknowledgementV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.target, self.owner, self.evidence, self.outcome.code()).cmp(&(
            other.target,
            other.owner,
            other.evidence,
            other.outcome.code(),
        ))
    }
}
impl PartialOrd for ErasureAcknowledgementV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Closed acknowledgement outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureAcknowledgementOutcomeV1 {
    /// Owner completed scoped work.
    Acknowledged,
    /// Owner could not complete scoped work.
    Negative,
    /// Owner evidence is stale.
    Stale,
}

impl ErasureAcknowledgementOutcomeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Acknowledged => 0,
            Self::Negative => 1,
            Self::Stale => 2,
        }
    }
    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Acknowledged),
            1 => Ok(Self::Negative),
            2 => Ok(Self::Stale),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// Structural evidence used to construct an ERC1 terminal receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureReceiptInputV1 {
    /// Request and terminal state.
    pub request: ErasureReferenceV1,
    /// Digest of the terminal ERS1 state which this receipt commits.
    pub terminal_state: ErasureReferenceV1,
    /// Coordinator identity which authorized the terminal ERS1 state.
    pub coordinator: ErasureReferenceV1,
    /// Complete or `PartialFailure` only.
    pub lifecycle: ErasureLifecycleV1,
    /// Access-freeze position.
    pub freeze_position: u64,
    /// Owner acknowledgements, canonicalized independently of arrival order.
    pub acknowledgements: Vec<ErasureAcknowledgementV1>,
    /// Authorized closure: each target must be resolved exactly once.
    pub required_targets: Vec<ErasureRequiredTargetV1>,
    /// Missing and failed owners.
    pub pending_owners: Vec<ErasureReferenceV1>,
    /// Failed owners.
    pub failed_owners: Vec<ErasureReferenceV1>,
    /// Ordered, payload-free artifact/key/replica/backup evidence.
    pub inventories: ErasureReceiptInventoriesV1,
    /// Replay claim and policy/trust/provenance evidence.
    pub replay_claim: ErasureReplayClaimV1,
    /// Policy version digest.
    pub policy: ErasureReferenceV1,
    /// Trust snapshot digest.
    pub trust: ErasureReferenceV1,
    /// Provenance digest.
    pub provenance: ErasureReferenceV1,
    /// Receipt position and signature digest.
    pub issue_position: u64,
    /// Receipt signature or commitment digest.
    pub signature: ErasureReferenceV1,
    /// Derived ERC1 digest, never supplied as authoritative input.
    pub receipt_digest: ErasureReferenceV1,
}

/// Payload-free, canonically ordered ERC1 receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureReceiptV1(ErasureReceiptInputV1);

impl ErasureReceiptV1 {
    /// Return the terminal outcome derived from the frozen closure.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.0.lifecycle
    }
    /// Return the weakest claim derived from the recorded inventory evidence.
    #[must_use]
    pub const fn replay_claim(&self) -> ErasureReplayClaimV1 {
        self.0.replay_claim
    }
    /// Validate ERC1 and normalize acknowledgement arrival order.
    ///
    /// # Errors
    ///
    /// Returns a closed error for incomplete or conflicting terminal evidence.
    pub fn new(mut input: ErasureReceiptInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if input.acknowledgements.len() > ERASURE_MAX_INVENTORY_RESULTS
            || input.required_targets.len() > ERASURE_MAX_INVENTORY_RESULTS
            || input.pending_owners.len() > ERASURE_MAX_REFERENCES
            || input.failed_owners.len() > ERASURE_MAX_REFERENCES
            || inventories_exceed_bound(&input.inventories)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if input.issue_position < input.freeze_position {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !inventory_transitions_preserve_or_weaken(&input.inventories) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        sort_inventories(&mut input.inventories);
        if !inventory_categories_match(&input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if inventories_have_duplicate_targets(&input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.acknowledgements.sort_unstable();
        input.required_targets.sort_unstable();
        input.pending_owners.sort_unstable();
        input.failed_owners.sort_unstable();
        if has_duplicate(&input.required_targets)
            || has_duplicate_by_target(&input.acknowledgements)
            || input
                .acknowledgements
                .iter()
                .any(|acknowledgement| acknowledgement.owner != acknowledgement.target.replica_id)
            || invalid_owner_sets(&input.pending_owners, &input.failed_owners)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&input.required_targets, &input.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (derived_pending, derived_failed) =
            derived_outcome_owners(&input.required_targets, &input.acknowledgements);
        if input.pending_owners != derived_pending || input.failed_owners != derived_failed {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !inventories_match_closure(&input.required_targets, &input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // The caller's claim is descriptive input only.  ERC1 records the
        // weakest claim disclosed by the per-artifact transitions.
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        let complete =
            acknowledgements_match_closure(&input.required_targets, &input.acknowledgements)
                && input
                    .acknowledgements
                    .iter()
                    .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let unresolved =
            !complete || !input.pending_owners.is_empty() || !input.failed_owners.is_empty();
        if input.lifecycle == ErasureLifecycleV1::Complete
            && (input.required_targets.is_empty() || !complete)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if input.lifecycle == ErasureLifecycleV1::PartialFailure && !unresolved {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        input.receipt_digest = reference_zero();
        Self(input).with_digest()
    }
    /// Encode exact-length deterministic ERC1.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if canonical serialization fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.clone().with_digest().and_then(|expected| {
            encode_limited(&receipt_value(&expected.0), ERASURE_RECEIPT_MAX_BYTES)
        })
    }
    /// Decode ERC1 structural evidence; call [`Self::verify_history`] to verify ERS1 ancestry.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or conflicting evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_RECEIPT_MAX_BYTES,
            ERASURE_MAX_INVENTORY_RESULTS,
        )
        .and_then(|value| exact_array(&value, 19).and_then(receipt_from_fields))
    }
    /// Return the terminal ERS1 digest bound into this receipt.
    #[must_use]
    pub const fn terminal_state(&self) -> ErasureReferenceV1 {
        self.0.terminal_state
    }
    /// Return the coordinator identity bound into this receipt.
    #[must_use]
    pub const fn coordinator(&self) -> ErasureReferenceV1 {
        self.0.coordinator
    }
    /// Return the derived receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> ErasureReferenceV1 {
        self.0.receipt_digest
    }
    /// Return the frozen required-target closure.
    #[must_use]
    pub fn required_targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.0.required_targets
    }
    /// Return the canonical acknowledgement closure.
    #[must_use]
    pub fn acknowledgements(&self) -> &[ErasureAcknowledgementV1] {
        &self.0.acknowledgements
    }
    /// Verify terminal binding and the bounded ERS1 predecessor chain via a host resolver.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or policy error when the resolver cannot prove the chain.
    pub fn verify_history<R: ErasureStateResolverV1>(
        &self,
        resolver: &R,
    ) -> Result<(), ErasureErrorV1> {
        match resolver.resolve_state(self.terminal_state()) {
            Ok(Some(terminal)) => {
                let matches_receipt = terminal.request() == self.0.request
                    && terminal.state_digest() == self.terminal_state()
                    && terminal.coordinator() == self.0.coordinator
                    && terminal.lifecycle() == self.0.lifecycle
                    && terminal.freeze_position() == Some(self.0.freeze_position)
                    && terminal.replay_claim() == self.0.replay_claim;
                if !matches_receipt {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                verify_predecessor_chain(terminal, resolver)
            }
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }
    fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        encode_limited(&receipt_core_value(&self.0), ERASURE_RECEIPT_MAX_BYTES).map(|bytes| {
            self.0.receipt_digest = ErasureReferenceV1::from_digest(domain_digest(ERC1, &bytes));
            self
        })
    }
}

fn derived_outcome_owners(
    required_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> (Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>) {
    let mut pending = required_targets
        .iter()
        .filter(|target| {
            !acknowledgements
                .iter()
                .any(|acknowledgement| acknowledgement.target == **target)
        })
        .map(|target| target.replica_id)
        .collect::<Vec<_>>();
    let mut failed = acknowledgements
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(|acknowledgement| acknowledgement.owner)
        .collect::<Vec<_>>();
    pending.sort_unstable();
    pending.dedup();
    failed.sort_unstable();
    failed.dedup();
    pending.retain(|owner| failed.binary_search(owner).is_err());
    (pending, failed)
}

/// Host-owned ERS1 lookup used to validate a receipt's predecessor chain.
pub trait ErasureStateResolverV1 {
    /// Resolve one digest without inventing a missing state.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or provenance error.
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<ErasureStateV1>, ErasureErrorV1>;
}

fn verify_predecessor_chain<R: ErasureStateResolverV1>(
    mut current: ErasureStateV1,
    resolver: &R,
) -> Result<(), ErasureErrorV1> {
    for _ in 0..8 {
        if let Some(previous_digest) = current.previous_state() {
            match resolver.resolve_state(previous_digest) {
                Ok(Some(previous)) => {
                    let predecessor_is_valid = [
                        previous.state_digest().eq(&previous_digest),
                        previous.request() == current.request(),
                        previous.coordinator() == current.coordinator(),
                        previous.lifecycle().permits(current.lifecycle()),
                        freeze_is_monotonic(previous.freeze_position(), current.freeze_position()),
                        previous
                            .replay_claim()
                            .preserves_or_weakens(current.replay_claim()),
                    ]
                    .into_iter()
                    .all(|valid| valid);
                    if !predecessor_is_valid {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                    current = previous;
                }
                Ok(None) => return Err(ErasureErrorV1::ProvenanceMissing),
                Err(error) => return Err(error),
            }
        } else if current.lifecycle() == ErasureLifecycleV1::Submitted {
            return Ok(());
        } else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
    }
    Err(ErasureErrorV1::ProvenanceMissing)
}

/// Host-owned port; adapters supply durable and irreversible work.
pub trait ErasureCoordinator {
    /// Record an idempotent ERQ1 request.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the request cannot be authenticated or stored.
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Authorize scope and advance ERS1.
    ///
    /// # Errors
    ///
    /// Returns a closed error if authorization or scope validation fails.
    fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Freeze access at the Tick Boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed error if freezing fails or conflicts.
    fn freeze_access(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Dispatch idempotent destruction work.
    ///
    /// # Errors
    ///
    /// Returns a closed error if dispatch cannot advance ERS1.
    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Persist a structurally bounded acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns a closed error for stale, unauthorized, or invalid evidence.
    fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Commit a payload-free terminal ERC1 receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed error if terminal evidence is insufficient.
    fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1>;
}

/// Host capability boundary used only for authentication and frozen target discovery.
pub trait ErasureCoordinatorPortV1 {
    /// Authenticate a request before the state machine records it.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::Unauthorized`] when the host rejects ERQ1.
    fn authenticate(&self, request: &ErasureRequestV1) -> Result<(), ErasureErrorV1>;
    /// Return the authoritative required-target closure at the freeze boundary.
    ///
    /// Once a matching `admit_freeze` succeeds, an exact retry for the same
    /// request must return the same sorted closure. The host must not replace
    /// a reserved closure with a later inventory while the V1 freeze admission
    /// is awaiting durable coordinator commit.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the host cannot freeze the inventory.
    fn required_targets(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1>;
    /// Authenticate and perform the freeze-boundary operation.
    ///
    /// The returned position and provenance are host-owned evidence.  The
    /// caller's transition values are treated as a request, never as proof.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the host cannot authenticate or perform the
    /// freeze boundary.
    ///
    /// A successful admission is a durable V1 reservation keyed by
    /// `request`. The host must retain the exact target closure, Tick Boundary
    /// position, and provenance returned for that request before returning.
    /// If the following `commit_record` fails, an exact retry must return the
    /// same admission rather than observe a later Tick Boundary or rediscover
    /// a different closure. This reservation is operational metadata; it does
    /// not replace the committed ERS1 record.
    fn admit_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureFreezeAdmissionV1, ErasureErrorV1>;
    /// Dispatch idempotent destruction commands for a frozen closure.
    ///
    /// The host must deduplicate by `(request, target)` and retain that
    /// identity across retries and process restarts.  The core state machine
    /// never advances to `DestructionDispatched` unless this call succeeds.
    ///
    /// # Errors
    ///
    /// Returns a closed operational error when dispatch cannot be accepted.
    fn dispatch_destruction(
        &self,
        request: ErasureReferenceV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<(), ErasureErrorV1>;
    /// Admit an acknowledgement from the authenticated owner and evidence boundary.
    ///
    /// The structural owner/target equality check in the core is necessary but
    /// not sufficient: digests are not identities or signatures.  The host
    /// must authenticate the sender and validate the evidence before this
    /// operation returns success.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::Unauthorized`] or a closed evidence error
    /// when the acknowledgement is not admitted by the host.
    fn admit_acknowledgement(
        &self,
        request: ErasureReferenceV1,
        acknowledgement: &ErasureAcknowledgementV1,
    ) -> Result<(), ErasureErrorV1>;
    /// Admit the policy, trust snapshot, and signature references before ERC1.
    ///
    /// These fields are commitments, not self-authenticating proof.  The host
    /// must verify them against its `TrustPolicyRegistry` and signature
    /// admission boundary before returning success.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::TrustSnapshotInvalid`] or a closed signature
    /// admission error when the evidence is not trusted.
    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1>;
    /// Load the durable coordinator record for a request.
    ///
    /// This is the authoritative source for lifecycle retries.  Returning
    /// `None` means that no ERQ1 has been committed; it must not be used as a
    /// reason to trust an in-memory cache after a restart.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or provenance error.
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1>;
    /// Atomically commit the next durable coordinator record.
    ///
    /// Implementations must make an exact record retry idempotent and reject
    /// conflicting replacement records.  The state machine treats this as
    /// the commit boundary for lifecycle and terminal receipt changes.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or conflicting-identity error.
    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1>;
}

/// Host-authenticated evidence for the access-freeze boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionV1 {
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Host-authenticated provenance for the freeze transition.
    pub provenance: ErasureReferenceV1,
}

/// Public durable fields for reconstructing an ERQ1/ERS1/ERC1 coordinator record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCoordinatorRecordPartsV1 {
    /// The exact authenticated request identity.
    pub request: ErasureRequestV1,
    /// The latest digest-linked ERS1 state.
    pub state: ErasureStateV1,
    /// The frozen required-target closure.
    pub targets: Vec<ErasureRequiredTargetV1>,
    /// Acknowledgements accepted for the frozen closure.
    pub acknowledgements: Vec<ErasureAcknowledgementV1>,
    /// The committed terminal receipt, if any.
    pub receipt: Option<ErasureReceiptV1>,
    /// Exact caller-supplied terminal input used for idempotent retries.
    pub receipt_input: Option<ErasureReceiptInputV1>,
    /// Authenticated authorization provenance, if present.
    pub authorize_provenance: Option<ErasureReferenceV1>,
    /// Host-authenticated freeze provenance, if present.
    pub freeze_provenance: Option<ErasureReferenceV1>,
    /// Host-authenticated dispatch provenance, if present.
    pub dispatch_provenance: Option<ErasureReferenceV1>,
}

/// Durable ERQ1/ERS1/ERC1 coordinator record.
///
/// Hosts persist this complete record (or an equivalent representation) and
/// return it from [`ErasureCoordinatorPortV1::load_record`].  The core state
/// machine keeps only a query cache; it never treats that cache as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCoordinatorRecordV1 {
    /// The exact authenticated request identity.
    request: ErasureRequestV1,
    /// The latest digest-linked ERS1 state.
    state: ErasureStateV1,
    /// The frozen required-target closure.
    targets: Vec<ErasureRequiredTargetV1>,
    /// Acknowledgements accepted for the frozen closure.
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    /// The committed terminal receipt, if any.
    receipt: Option<ErasureReceiptV1>,
    /// Exact caller-supplied terminal input used for idempotent retries.
    receipt_input: Option<ErasureReceiptInputV1>,
    authorize_provenance: Option<ErasureReferenceV1>,
    freeze_provenance: Option<ErasureReferenceV1>,
    dispatch_provenance: Option<ErasureReferenceV1>,
}

impl ErasureCoordinatorRecordV1 {
    /// Reconstruct a durable coordinator record from host storage.
    ///
    /// Hosts may persist the returned public fields in any representation and
    /// must validate the complete record again when rehydrating it.  This
    /// constructor is the only supported boundary for records loaded by a
    /// [`ErasureCoordinatorPortV1`].
    ///
    /// # Errors
    ///
    /// Returns a closed error when the persisted record is inconsistent with
    /// the coordinator, lifecycle, closure, provenance, or terminal receipt.
    pub fn from_parts(
        parts: ErasureCoordinatorRecordPartsV1,
        coordinator: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        let record = Self {
            request: parts.request,
            state: parts.state,
            targets: parts.targets,
            acknowledgements: parts.acknowledgements,
            receipt: parts.receipt,
            receipt_input: parts.receipt_input,
            authorize_provenance: parts.authorize_provenance,
            freeze_provenance: parts.freeze_provenance,
            dispatch_provenance: parts.dispatch_provenance,
        };
        record.validate(coordinator).map(|()| record)
    }

    /// Return the authenticated ERQ1 request.
    #[must_use]
    pub const fn request(&self) -> &ErasureRequestV1 {
        &self.request
    }

    /// Return the latest digest-linked ERS1 state.
    #[must_use]
    pub const fn state(&self) -> &ErasureStateV1 {
        &self.state
    }

    /// Return the frozen required-target closure.
    #[must_use]
    pub fn targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.targets
    }

    /// Return acknowledgements accepted for the frozen closure.
    #[must_use]
    pub fn acknowledgements(&self) -> &[ErasureAcknowledgementV1] {
        &self.acknowledgements
    }

    /// Return the committed terminal receipt, if any.
    #[must_use]
    pub const fn receipt(&self) -> Option<&ErasureReceiptV1> {
        self.receipt.as_ref()
    }

    /// Return the exact terminal input admitted for idempotent retries.
    #[must_use]
    pub const fn receipt_input(&self) -> Option<&ErasureReceiptInputV1> {
        self.receipt_input.as_ref()
    }

    /// Return the authenticated authorization provenance, if present.
    #[must_use]
    pub const fn authorize_provenance(&self) -> Option<ErasureReferenceV1> {
        self.authorize_provenance
    }

    /// Return the host-authenticated freeze provenance, if present.
    #[must_use]
    pub const fn freeze_provenance(&self) -> Option<ErasureReferenceV1> {
        self.freeze_provenance
    }

    /// Return the host-authenticated dispatch provenance, if present.
    #[must_use]
    pub const fn dispatch_provenance(&self) -> Option<ErasureReferenceV1> {
        self.dispatch_provenance
    }

    fn validate(&self, coordinator: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        if self.request.reference() != self.state.request()
            || self.state.coordinator() != coordinator
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if !self.targets.windows(2).all(|pair| pair[0] < pair[1])
            || has_duplicate_by_target(&self.acknowledgements)
            || self
                .acknowledgements
                .iter()
                .any(|ack| ack.owner != ack.target.replica_id)
            || !acknowledgements_are_closure_subset(&self.targets, &self.acknowledgements)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let lifecycle = self.state.lifecycle();
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::Rejected
        ) && (!self.targets.is_empty()
            || !self.acknowledgements.is_empty()
            || self.receipt.is_some()
            || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::AccessFrozen
            && (self.targets.is_empty()
                || !self.acknowledgements.is_empty()
                || self.receipt.is_some()
                || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
        ) && (self.targets.is_empty() || self.receipt.is_some() || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let operation_provenance_count = [
            self.authorize_provenance,
            self.freeze_provenance,
            self.dispatch_provenance,
        ]
        .into_iter()
        .flatten()
        .count();
        let expected_operation_count = match lifecycle {
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Rejected => 0,
            ErasureLifecycleV1::Authorized => 1,
            ErasureLifecycleV1::AccessFrozen => 2,
            ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => 3,
        };
        if operation_provenance_count != expected_operation_count {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if lifecycle.is_terminal() {
            let Some(receipt) = self.receipt.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            if self.receipt_input.is_none() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            let mut acknowledgements = self.acknowledgements.clone();
            acknowledgements.sort_unstable();
            if receipt.terminal_state() != self.state.state_digest()
                || receipt.lifecycle() != lifecycle
                || receipt.coordinator() != coordinator
                || receipt.0.request != self.request.reference()
                || receipt.required_targets() != self.targets.as_slice()
                || receipt.acknowledgements() != acknowledgements.as_slice()
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let complete = acknowledgements_match_closure(&self.targets, &self.acknowledgements)
                && self
                    .acknowledgements
                    .iter()
                    .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
            if (lifecycle == ErasureLifecycleV1::Complete) != complete {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let (pending, failed) = derived_outcome_owners(&self.targets, &self.acknowledgements);
            if self.state.pending_owners() != pending.as_slice()
                || self.state.failed_owners() != failed.as_slice()
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        Ok(())
    }
}

/// Core-owned, idempotent ERQ1/ERS1/ERC1 state machine; adapters cannot bypass it.
pub struct ErasureCoordinatorStateMachineV1<P> {
    port: P,
    coordinator: ErasureReferenceV1,
    records: Vec<ErasureCoordinatorRecordV1>,
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinatorStateMachineV1<P> {
    /// Construct a host-owned state machine.
    #[must_use]
    pub const fn new(port: P, coordinator: ErasureReferenceV1) -> Self {
        Self {
            port,
            coordinator,
            records: Vec::new(),
        }
    }
    fn cache(&mut self, record: ErasureCoordinatorRecordV1) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|existing| existing.request.reference() == record.request.reference())
        {
            *existing = record;
        } else {
            self.records.push(record);
        }
    }
    fn record(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureCoordinatorRecordV1, ErasureErrorV1> {
        match self.port.load_record(request) {
            Ok(Some(record)) => record.validate(self.coordinator).map(|()| {
                self.cache(record.clone());
                record
            }),
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }
    fn commit(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        record
            .validate(self.coordinator)
            .and_then(|()| self.port.commit_record(record.clone()))
            .map(|()| self.cache(record))
    }
    /// Query an existing outcome without creating or advancing it.
    #[must_use]
    pub fn existing(&self, request: ErasureReferenceV1) -> Option<&ErasureStateV1> {
        self.records
            .iter()
            .find(|record| record.request.reference() == request)
            .map(|record| &record.state)
    }
    /// Authenticate and idempotently submit ERQ1.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication or conflicting-identity error.
    pub fn submit(
        &mut self,
        request: ErasureRequestV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        match self.port.load_record(request.reference()) {
            Ok(Some(record)) => record.validate(self.coordinator).and_then(|()| {
                if record.request.eq(&request) {
                    let state = record.state.clone();
                    self.cache(record);
                    Ok(state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                }
            }),
            Ok(None) => self.port.authenticate(&request).and_then(|()| {
                ErasureStateV1::submitted(request.reference(), self.coordinator, provenance)
                    .and_then(|state| {
                        let record = ErasureCoordinatorRecordV1 {
                            request,
                            state: state.clone(),
                            targets: Vec::new(),
                            acknowledgements: Vec::new(),
                            receipt: None,
                            receipt_input: None,
                            authorize_provenance: None,
                            freeze_provenance: None,
                            dispatch_provenance: None,
                        };
                        self.commit(record).map(|()| state)
                    })
            }),
            Err(error) => Err(error),
        }
    }
    /// Authorize a submitted ERQ1; an exact lifecycle retry is a query.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown request, an injected freeze, or a
    /// non-monotonic state transition.
    pub fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
                return if record.authorize_provenance == Some(provenance)
                    && (record.state.lifecycle() == ErasureLifecycleV1::Authorized
                        || record.state.lifecycle().is_terminal()
                        || record.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
                        || record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched
                        || record.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements)
                {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            let replay_claim = record.state.replay_claim();
            record
                .state
                .transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::Authorized,
                    freeze_position: None,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim,
                    provenance,
                })
                .and_then(|state| {
                    record.state = state;
                    record.authorize_provenance = Some(provenance);
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Freeze the authoritative closure once; duplicate freezes before dispatch
    /// return the existing state. Later lifecycle retries use their own edges.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle or inventory error.
    pub fn freeze_inventory(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let requested_transition = transition;
        self.record(request).and_then(|mut record| {
            if record.freeze_provenance.is_some() {
                return if requested_transition.lifecycle == ErasureLifecycleV1::AccessFrozen {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            let freeze_is_authorized = matches!(
                (record.state.lifecycle(), requested_transition.lifecycle),
                (
                    ErasureLifecycleV1::Authorized,
                    ErasureLifecycleV1::AccessFrozen
                )
            );
            if !freeze_is_authorized {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port.required_targets(request).and_then(|mut targets| {
                if targets.is_empty() || targets.len() > ERASURE_MAX_INVENTORY_RESULTS {
                    return Err(ErasureErrorV1::ScopeInvalid);
                }
                targets.sort_unstable();
                if has_duplicate(&targets) {
                    return Err(ErasureErrorV1::ScopeInvalid);
                }
                self.port
                    .admit_freeze(request, &requested_transition)
                    .and_then(|admission| {
                        let provenance = admission.provenance;
                        let replay_claim = record.state.replay_claim();
                        record
                            .state
                            .transition(ErasureStateTransitionV1 {
                                lifecycle: ErasureLifecycleV1::AccessFrozen,
                                freeze_position: Some(admission.freeze_position),
                                pending_owners: Vec::new(),
                                failed_owners: Vec::new(),
                                acknowledged_targets: Vec::new(),
                                replay_claim,
                                provenance,
                            })
                            .map(|state| (state, provenance))
                    })
                    .and_then(|(state, provenance)| {
                        record.state = state;
                        record.freeze_provenance = Some(provenance);
                        record.targets = targets;
                        let state = record.state.clone();
                        self.commit(record).map(|()| state)
                    })
            })
        })
    }
    /// Dispatch the frozen closure through the host-owned idempotent port.
    ///
    /// A caller cannot claim this lifecycle edge by supplying an ERS1
    /// transition.  The host dispatch must succeed before the durable state is
    /// committed.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the request is unknown, the lifecycle is
    /// invalid, host dispatch is rejected, or the durable commit fails.
    pub fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
                    | ErasureLifecycleV1::Complete
                    | ErasureLifecycleV1::PartialFailure
            ) {
                return if record.dispatch_provenance == Some(provenance) {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            if record.state.lifecycle() != ErasureLifecycleV1::AccessFrozen {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port
                .dispatch_destruction(request, &record.targets)
                .and_then(|()| {
                    let freeze_position = record.state.freeze_position();
                    let replay_claim = record.state.replay_claim();
                    record.state.transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::DestructionDispatched,
                        freeze_position,
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim,
                        provenance,
                    })
                })
                .and_then(|state| {
                    record.state = state;
                    record.dispatch_provenance = Some(provenance);
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Persist one frozen-closure acknowledgement; an exact retry is idempotent.
    ///
    /// # Errors
    ///
    /// Returns unauthorized for an injected target and policy conflict for a conflicting retry.
    pub fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.acknowledgements.contains(&acknowledgement) {
                return Ok(record.state);
            }
            if !matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            if !record.targets.contains(&acknowledgement.target)
                || acknowledgement.owner != acknowledgement.target.replica_id
            {
                return Err(ErasureErrorV1::Unauthorized);
            }
            if record
                .acknowledgements
                .iter()
                .any(|existing| existing.target == acknowledgement.target)
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port
                .admit_acknowledgement(request, &acknowledgement)
                .and_then(|()| {
                    record.acknowledgements.push(acknowledgement);
                    record.acknowledgements.sort_unstable();
                    if record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched {
                        let freeze_position = record.state.freeze_position();
                        let replay_claim = record.state.replay_claim();
                        let provenance = record
                            .acknowledgements
                            .last()
                            .map_or(reference_zero(), |ack| ack.evidence);
                        record
                            .state
                            .transition(ErasureStateTransitionV1 {
                                lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                                freeze_position,
                                pending_owners: Vec::new(),
                                failed_owners: Vec::new(),
                                acknowledged_targets: Vec::new(),
                                replay_claim,
                                provenance,
                            })
                            .map(|state| {
                                record.state = state;
                            })
                    } else {
                        Ok(())
                    }
                })
                .and_then(|()| {
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Commit a receipt only when its closure and acknowledgement evidence match this record.
    ///
    /// A terminal retry must reproduce the exact input admitted for that
    /// receipt.  Core-derived ERC1 fields are normalized only on the first
    /// commit; changing them on a retry is a conflicting operation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for injected evidence or a conflicting terminal retry.
    pub fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if let Some(stored) = record.receipt.clone() {
                return if record.receipt_input.as_ref() == Some(&input) {
                    Ok(stored)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            if record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched {
                let freeze_position = record.state.freeze_position();
                let replay_claim = record.state.replay_claim();
                let provenance = input.provenance;
                let awaiting = record.state.transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                    freeze_position,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim,
                    provenance,
                });
                return awaiting.and_then(|state| {
                    record.state = state;
                    let awaiting_record = record.clone();
                    Self::prepare_finalization(self, request, &mut record, input).and_then(
                        |(terminal_record, receipt)| {
                            self.commit(awaiting_record)
                                .and_then(|()| self.commit(terminal_record))
                                .map(|()| receipt)
                        },
                    )
                });
            }
            Self::finalize_record(self, request, &mut record, input)
        })
    }

    fn normalize_receipt_input(
        request: ErasureReferenceV1,
        coordinator: ErasureReferenceV1,
        record: &ErasureCoordinatorRecordV1,
        mut input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptInputV1, ErasureErrorV1> {
        let Some(freeze_position) = record.state.freeze_position() else {
            return Err(ErasureErrorV1::PolicyConflict);
        };
        if !record.state.lifecycle().is_terminal() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        input.request = request;
        input.coordinator = coordinator;
        input.terminal_state = record.state.state_digest();
        input.lifecycle = record.state.lifecycle();
        input.freeze_position = freeze_position;
        input.required_targets.clone_from(&record.targets);
        input.acknowledgements.clone_from(&record.acknowledgements);
        input.pending_owners = record.state.pending_owners().to_vec();
        input.failed_owners = record.state.failed_owners().to_vec();
        Ok(input)
    }

    fn receipt_input_matches_authority(
        input: &ErasureReceiptInputV1,
        normalized: &ErasureReceiptInputV1,
    ) -> bool {
        input.request == normalized.request
            && input.coordinator == normalized.coordinator
            && input.terminal_state == normalized.terminal_state
            && input.lifecycle == normalized.lifecycle
            && input.freeze_position == normalized.freeze_position
            && input.required_targets == normalized.required_targets
            && input.acknowledgements == normalized.acknowledgements
            && input.pending_owners == normalized.pending_owners
            && input.failed_owners == normalized.failed_owners
    }

    fn finalize_record(
        &mut self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        Self::prepare_finalization(self, request, record, input)
            .and_then(|(terminal_record, receipt)| self.commit(terminal_record).map(|()| receipt))
    }

    fn prepare_finalization(
        &self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: ErasureReceiptInputV1,
    ) -> Result<(ErasureCoordinatorRecordV1, ErasureReceiptV1), ErasureErrorV1> {
        if record.state.lifecycle() != ErasureLifecycleV1::AwaitingAcknowledgements {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        record.receipt_input = Some(input.clone());
        let complete = acknowledgements_match_closure(&record.targets, &record.acknowledgements)
            && record
                .acknowledgements
                .iter()
                .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let lifecycle = if complete {
            ErasureLifecycleV1::Complete
        } else {
            ErasureLifecycleV1::PartialFailure
        };
        let mut pending_owners: Vec<_> = record
            .targets
            .iter()
            .filter(|target| {
                !record
                    .acknowledgements
                    .iter()
                    .any(|ack| ack.target == **target)
            })
            .map(|target| target.replica_id)
            .collect();
        let mut failed_owners: Vec<_> = record
            .acknowledgements
            .iter()
            .filter(|ack| ack.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged)
            .map(|ack| ack.owner)
            .collect();
        pending_owners.sort_unstable();
        pending_owners.dedup();
        failed_owners.sort_unstable();
        failed_owners.dedup();
        pending_owners.retain(|owner| failed_owners.binary_search(owner).is_err());
        let replay_claim = weakest_inventory_claim(&input.inventories);
        let freeze_position = record.state.freeze_position();
        record
            .state
            .transition(ErasureStateTransitionV1 {
                lifecycle,
                freeze_position,
                pending_owners,
                failed_owners,
                acknowledged_targets: if complete {
                    record.targets.clone()
                } else {
                    Vec::new()
                },
                replay_claim,
                provenance: input.provenance,
            })
            .and_then(|terminal| {
                record.state = terminal;
                Self::normalize_receipt_input(request, self.coordinator, record, input.clone())
                    .and_then(|normalized| {
                        if Self::receipt_input_matches_authority(&input, &normalized) {
                            record.receipt_input = Some(input);
                            Ok(normalized)
                        } else {
                            Err(ErasureErrorV1::PolicyConflict)
                        }
                    })
            })
            .and_then(|normalized| self.port.admit_receipt(&normalized).map(|()| normalized))
            .and_then(ErasureReceiptV1::new)
            .inspect(|receipt| {
                record.receipt = Some(receipt.clone());
            })
            .map(|receipt| (record.clone(), receipt))
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinator for ErasureCoordinatorStateMachineV1<P> {
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        let provenance = request.provenance();
        Self::submit(self, request, provenance)
    }

    fn authorize(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::authorize(self, request, provenance)
    }

    fn freeze_access(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::freeze_inventory(self, request, transition)
    }

    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::dispatch_destruction(self, request, provenance)
    }

    fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::acknowledge(self, request, acknowledgement)
    }

    fn finalize(
        &mut self,
        request: ErasureReferenceV1,
        input: ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        Self::finalize(self, request, input)
    }
}

#[path = "erasure_codec.rs"]
mod codec;
use codec::{
    acknowledgements_are_closure_subset, acknowledgements_match_closure, decode_limited,
    domain_digest, encode_canonical, encode_limited, exact_array, freeze_is_monotonic,
    has_duplicate, has_duplicate_by_target, invalid_owner_sets, inventories_exceed_bound,
    inventories_have_duplicate_targets, inventories_match_closure, inventory_categories_match,
    inventory_transitions_preserve_or_weaken, receipt_core_value, receipt_from_fields,
    receipt_value, reference_zero, request_from_fields, request_value, sort_inventories,
    state_core_value, state_from_fields, state_value, weakest_inventory_claim,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "erasure_tests.rs"]
mod tests;
