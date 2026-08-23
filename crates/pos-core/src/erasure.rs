//! ADR-060's payload-free ERQ1, ERS1, and ERC1 public contracts.
//!
//! This module deliberately excludes storage, key destruction, artifact work,
//! backup inventory, and replay evaluation. Those operations belong to the
//! adapters and follow-up tickets named by ADR-060.

use std::cmp::Ordering;
use std::io::Cursor;

use ciborium::value::Value;

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
        decode_limited(bytes, ERASURE_REQUEST_OR_STATE_MAX_BYTES)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureInventoryResultV1 {
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
    pub fn transition(&self, mut change: ErasureStateTransitionV1) -> Result<Self, ErasureErrorV1> {
        if !self.lifecycle.permits(change.lifecycle)
            || !freeze_is_monotonic(self.freeze_position, change.freeze_position)
            || !self.replay_claim.preserves_or_weakens(change.replay_claim)
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
        decode_limited(bytes, ERASURE_REQUEST_OR_STATE_MAX_BYTES)
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
        if inventories_have_duplicate_targets(&input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.acknowledgements.sort_unstable();
        input.required_targets.sort_unstable();
        input.pending_owners.sort_unstable();
        input.failed_owners.sort_unstable();
        if has_duplicate(&input.required_targets)
            || has_duplicate_by_target(&input.acknowledgements)
            || invalid_owner_sets(&input.pending_owners, &input.failed_owners)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&input.required_targets, &input.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !inventories_match_closure(&input.required_targets, &input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let complete = acknowledgements_match_closure(&input.required_targets, &input.acknowledgements)
            && input.acknowledgements.iter().all(|ack| {
            ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
        });
        let unresolved = !complete
            || !input.pending_owners.is_empty()
            || !input.failed_owners.is_empty();
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
        decode_limited(bytes, ERASURE_RECEIPT_MAX_BYTES)
            .and_then(|value| exact_array(&value, 18).and_then(receipt_from_fields))
    }
    /// Return the terminal ERS1 digest bound into this receipt.
    #[must_use]
    pub const fn terminal_state(&self) -> ErasureReferenceV1 {
        self.0.terminal_state
    }
    /// Return the derived receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> ErasureReferenceV1 {
        self.0.receipt_digest
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
                if terminal.request() != self.0.request
                    || terminal.lifecycle() != self.0.lifecycle
                    || terminal.freeze_position() != Some(self.0.freeze_position)
                    || terminal.replay_claim() != self.0.replay_claim
                {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                verify_predecessor_chain(terminal, resolver)
            }
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }
    fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        receipt_core_value(&self.0)
            .and_then(|value| encode_limited(&value, ERASURE_RECEIPT_MAX_BYTES))
            .map(|bytes| {
                self.0.receipt_digest = ErasureReferenceV1::from_digest(domain_digest(ERC1, &bytes));
                self
            })
    }
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
                    if previous.state_digest() != previous_digest
                        || !previous.lifecycle().permits(current.lifecycle())
                        || !freeze_is_monotonic(previous.freeze_position(), current.freeze_position())
                        || !previous
                            .replay_claim()
                            .preserves_or_weakens(current.replay_claim())
                    {
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
    fn authorize(&mut self, request: ErasureReferenceV1) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Freeze access at the Tick Boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed error if freezing fails or conflicts.
    fn freeze_access(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Dispatch idempotent destruction work.
    ///
    /// # Errors
    ///
    /// Returns a closed error if dispatch cannot advance ERS1.
    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
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
    fn finalize(&mut self, request: ErasureReferenceV1)
        -> Result<ErasureReceiptV1, ErasureErrorV1>;
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
    /// # Errors
    ///
    /// Returns a closed error when the host cannot freeze the inventory.
    fn required_targets(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1>;
}

#[derive(Clone, Debug)]
struct ErasureCoordinatorRecordV1 {
    request: ErasureRequestV1,
    state: ErasureStateV1,
    targets: Vec<ErasureRequiredTargetV1>,
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    receipt: Option<ErasureReceiptV1>,
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
        Self { port, coordinator, records: Vec::new() }
    }
    /// Query an existing outcome without creating or advancing it.
    #[must_use]
    pub fn existing(&self, request: ErasureReferenceV1) -> Option<&ErasureStateV1> {
        self.records.iter().find(|record| record.request.reference() == request).map(|record| &record.state)
    }
    /// Authenticate and idempotently submit ERQ1.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication or conflicting-identity error.
    pub fn submit(&mut self, request: ErasureRequestV1, provenance: ErasureReferenceV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        if let Some(record) = self.records.iter().find(|record| record.request.reference() == request.reference()) {
            return if record.request == request { Ok(record.state.clone()) } else { Err(ErasureErrorV1::PolicyConflict) };
        }
        self.port.authenticate(&request).and_then(|()| {
            ErasureStateV1::submitted(request.reference(), self.coordinator, provenance).inspect(|state| {
                self.records.push(ErasureCoordinatorRecordV1 { request, state: state.clone(), targets: Vec::new(), acknowledgements: Vec::new(), receipt: None });
            })
        })
    }
    /// Advance one non-freeze ERS1 edge; an exact lifecycle retry is a query.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown request, an injected freeze, or a
    /// non-monotonic state transition.
    pub fn advance(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let Some(record) = self.records.iter_mut().find(|record| record.request.reference() == request) else { return Err(ErasureErrorV1::ProvenanceMissing); };
        if record.state.lifecycle() == transition.lifecycle {
            return Ok(record.state.clone());
        }
        if transition.lifecycle == ErasureLifecycleV1::AccessFrozen {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        record.state.transition(transition).inspect(|state| {
            record.state = state.clone();
        })
    }
    /// Freeze the authoritative closure once; duplicate freezes return the existing state.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle or inventory error.
    pub fn freeze_inventory(&mut self, request: ErasureReferenceV1, transition: ErasureStateTransitionV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        let Some(index) = self.records.iter().position(|record| record.request.reference() == request) else { return Err(ErasureErrorV1::ProvenanceMissing); };
        if self.records[index].state.lifecycle() == ErasureLifecycleV1::AccessFrozen { return Ok(self.records[index].state.clone()); }
        if self.records[index].state.lifecycle() != ErasureLifecycleV1::Authorized
            || transition.lifecycle != ErasureLifecycleV1::AccessFrozen
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port.required_targets(request).and_then(|mut targets| {
            if targets.is_empty() || targets.len() > ERASURE_MAX_INVENTORY_RESULTS { return Err(ErasureErrorV1::ScopeInvalid); }
            targets.sort_unstable();
            if has_duplicate(&targets) { return Err(ErasureErrorV1::ScopeInvalid); }
            self.records[index].state.transition(transition).inspect(|state| { self.records[index].targets = targets; self.records[index].state = state.clone(); })
        })
    }
    /// Persist one frozen-closure acknowledgement; an exact retry is idempotent.
    ///
    /// # Errors
    ///
    /// Returns unauthorized for an injected target and policy conflict for a conflicting retry.
    pub fn acknowledge(&mut self, request: ErasureReferenceV1, acknowledgement: ErasureAcknowledgementV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        let Some(record) = self.records.iter_mut().find(|record| record.request.reference() == request) else { return Err(ErasureErrorV1::ProvenanceMissing); };
        if !matches!(record.state.lifecycle(), ErasureLifecycleV1::DestructionDispatched | ErasureLifecycleV1::AwaitingAcknowledgements) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !record.targets.contains(&acknowledgement.target) { return Err(ErasureErrorV1::Unauthorized); }
        if record.acknowledgements.contains(&acknowledgement) { return Ok(record.state.clone()); }
        if record.acknowledgements.iter().any(|existing| existing.target == acknowledgement.target) { return Err(ErasureErrorV1::PolicyConflict); }
        record.acknowledgements.push(acknowledgement);
        if record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched {
            record.state.transition(ErasureStateTransitionV1 {
                lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                freeze_position: record.state.freeze_position(),
                pending_owners: Vec::new(),
                failed_owners: Vec::new(),
                replay_claim: record.state.replay_claim(),
                provenance: record.acknowledgements.last().map_or(reference_zero(), |ack| ack.evidence),
            }).inspect(|state| { record.state = state.clone(); })
        } else {
            Ok(record.state.clone())
        }
    }
    /// Commit a receipt only when its closure and acknowledgement evidence match this record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for injected evidence or a conflicting terminal retry.
    pub fn finalize(&mut self, request: ErasureReferenceV1, mut input: ErasureReceiptInputV1) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        let Some(record) = self.records.iter_mut().find(|record| record.request.reference() == request) else { return Err(ErasureErrorV1::ProvenanceMissing); };
        if let Some(receipt) = &record.receipt { return Ok(receipt.clone()); }
        if record.state.lifecycle() != ErasureLifecycleV1::AwaitingAcknowledgements {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let complete = acknowledgements_match_closure(&record.targets, &record.acknowledgements) && record.acknowledgements.iter().all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let lifecycle = if complete { ErasureLifecycleV1::Complete } else { ErasureLifecycleV1::PartialFailure };
        let mut pending_owners: Vec<_> = record.targets.iter().filter(|target| !record.acknowledgements.iter().any(|ack| ack.target == **target)).map(|target| target.replica_id).collect();
        let mut failed_owners: Vec<_> = record.acknowledgements.iter().filter(|ack| ack.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged).map(|ack| ack.owner).collect();
        pending_owners.sort_unstable();
        pending_owners.dedup();
        failed_owners.sort_unstable();
        failed_owners.dedup();
        pending_owners.retain(|owner| failed_owners.binary_search(owner).is_err());
        record.state.transition(ErasureStateTransitionV1 {
            lifecycle,
            freeze_position: record.state.freeze_position(),
            pending_owners,
            failed_owners,
            replay_claim: input.replay_claim,
            provenance: input.provenance,
        }).and_then(|terminal| {
            input.request = request;
            input.terminal_state = terminal.state_digest();
            input.required_targets.clone_from(&record.targets);
            input.acknowledgements.clone_from(&record.acknowledgements);
            input.lifecycle = lifecycle;
            if let Some(freeze_position) = terminal.freeze_position() {
                input.freeze_position = freeze_position;
                input.pending_owners = terminal.pending_owners().to_vec();
                input.failed_owners = terminal.failed_owners().to_vec();
                ErasureReceiptV1::new(input).inspect(|receipt| { record.state = terminal; record.receipt = Some(receipt.clone()); })
            } else {
                Err(ErasureErrorV1::PolicyConflict)
            }
        })
    }
}

fn request_value(input: &ErasureRequestInputV1) -> Value {
    Value::Array(vec![
        text(ERQ1),
        uint(VERSION),
        digest(input.request),
        digest(input.subject),
        uint(input.scope.code()),
        references_value(&input.selectors),
        digest(input.requester),
        digest(input.authorization),
        digest(input.policy),
        uint(input.request_position),
        uint(input.horizon_position),
        digest(input.provenance),
    ])
}
fn request_from_fields(fields: &[Value]) -> Result<ErasureRequestV1, ErasureErrorV1> {
    header(fields, ERQ1).and_then(|()| {
        request_identity(fields).and_then(|(request, subject, scope, selectors)| {
            request_authority(fields).and_then(|(requester, authorization, policy)| {
                request_positions(fields).and_then(
                    |(request_position, horizon_position, provenance)| {
                        ErasureRequestV1::new(ErasureRequestInputV1 {
                            request,
                            subject,
                            scope,
                            selectors,
                            requester,
                            authorization,
                            policy,
                            request_position,
                            horizon_position,
                            provenance,
                        })
                    },
                )
            })
        })
    })
}
fn request_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureScopeV1,
        Vec<ErasureReferenceV1>,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        bytes32(&fields[3]).and_then(|subject| {
            unsigned(&fields[4])
                .and_then(ErasureScopeV1::from_code)
                .and_then(|scope| {
                    references_from_value(&fields[5], true)
                        .map(|selectors| (request, subject, scope, selectors))
                })
        })
    })
}
fn request_authority(
    fields: &[Value],
) -> Result<(ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1), ErasureErrorV1> {
    bytes32(&fields[6]).and_then(|requester| {
        bytes32(&fields[7]).and_then(|authorization| {
            bytes32(&fields[8]).map(|policy| (requester, authorization, policy))
        })
    })
}
fn request_positions(fields: &[Value]) -> Result<(u64, u64, ErasureReferenceV1), ErasureErrorV1> {
    unsigned(&fields[9]).and_then(|request_position| {
        unsigned(&fields[10]).and_then(|horizon_position| {
            bytes32(&fields[11]).map(|provenance| (request_position, horizon_position, provenance))
        })
    })
}
fn state_core_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
    ])
}
fn state_value(state: &ErasureStateV1) -> Value {
    Value::Array(vec![
        text(ERS1),
        uint(VERSION),
        digest(state.request),
        uint(state.lifecycle.code()),
        optional_uint(state.freeze_position),
        digest(state.coordinator),
        references_value(&state.pending_owners),
        references_value(&state.failed_owners),
        uint(state.replay_claim.code()),
        optional_digest(state.previous_state),
        digest(state.provenance),
        digest(state.state_digest),
    ])
}
fn state_from_fields(fields: &[Value]) -> Result<ErasureStateV1, ErasureErrorV1> {
    header(fields, ERS1).and_then(|()| {
        state_identity(fields).and_then(|(request, lifecycle, freeze_position, coordinator)| {
            state_owners(fields).and_then(|(pending_owners, failed_owners, replay_claim)| {
                state_provenance(fields).and_then(|(previous_state, provenance, state_digest)| {
                    let state = ErasureStateV1 {
                        request,
                        lifecycle,
                        freeze_position,
                        coordinator,
                        pending_owners,
                        failed_owners,
                        replay_claim,
                        previous_state,
                        provenance,
                        state_digest,
                    };
                    state.validate().and_then(|()| {
                        state.clone().with_digest().and_then(|expected| {
                            if expected.state_digest == state.state_digest {
                                Ok(state)
                            } else {
                                Err(ErasureErrorV1::ProvenanceMissing)
                            }
                        })
                    })
                })
            })
        })
    })
}
fn state_identity(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureLifecycleV1,
        Option<u64>,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[2]).and_then(|request| {
        unsigned(&fields[3])
            .and_then(ErasureLifecycleV1::from_code)
            .and_then(|lifecycle| {
                optional_unsigned(&fields[4]).and_then(|freeze_position| {
                    bytes32(&fields[5])
                        .map(|coordinator| (request, lifecycle, freeze_position, coordinator))
                })
            })
    })
}
fn state_owners(
    fields: &[Value],
) -> Result<
    (
        Vec<ErasureReferenceV1>,
        Vec<ErasureReferenceV1>,
        ErasureReplayClaimV1,
    ),
    ErasureErrorV1,
> {
    references_from_value(&fields[6], false).and_then(|pending_owners| {
        references_from_value(&fields[7], false).and_then(|failed_owners| {
            unsigned(&fields[8])
                .and_then(ErasureReplayClaimV1::from_code)
                .map(|replay_claim| (pending_owners, failed_owners, replay_claim))
        })
    })
}
fn state_provenance(
    fields: &[Value],
) -> Result<
    (
        Option<ErasureReferenceV1>,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    optional_bytes32(&fields[9]).and_then(|previous_state| {
        bytes32(&fields[10]).and_then(|provenance| {
            bytes32(&fields[11]).map(|state_digest| (previous_state, provenance, state_digest))
        })
    })
}
fn receipt_value(input: &ErasureReceiptInputV1) -> Value {
    Value::Array(vec![
        text(ERC1),
        uint(VERSION),
        digest(input.request),
        digest(input.terminal_state),
        uint(input.lifecycle.code()),
        uint(input.freeze_position),
        targets_value(&input.required_targets),
        Value::Array(
            input
                .acknowledgements
                .iter()
                .copied()
                .map(acknowledgement_value)
                .collect(),
        ),
        references_value(&input.pending_owners),
        references_value(&input.failed_owners),
        inventories_value(&input.inventories),
        uint(input.replay_claim.code()),
        digest(input.policy),
        digest(input.trust),
        digest(input.provenance),
        uint(input.issue_position),
        digest(input.receipt_digest),
        digest(input.signature),
    ])
}
fn receipt_core_value(input: &ErasureReceiptInputV1) -> Result<Value, ErasureErrorV1> {
    let Value::Array(mut fields) = receipt_value(input) else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    fields.remove(16);
    Ok(Value::Array(fields))
}
fn acknowledgement_value(ack: ErasureAcknowledgementV1) -> Value {
    Value::Array(vec![
        target_value(ack.target),
        digest(ack.owner),
        digest(ack.evidence),
        uint(ack.outcome.code()),
    ])
}
fn receipt_from_fields(fields: &[Value]) -> Result<ErasureReceiptV1, ErasureErrorV1> {
    header(fields, ERC1).and_then(|()| {
        bytes32(&fields[2]).and_then(|request| {
            bytes32(&fields[3]).and_then(|terminal_state| {
                unsigned(&fields[4])
                    .and_then(ErasureLifecycleV1::from_code)
                    .and_then(|lifecycle| {
                        unsigned(&fields[5]).and_then(|freeze_position| {
                            targets_from_value(&fields[6]).and_then(|required_targets| {
                                acknowledgements_from_value(&fields[7]).and_then(|acknowledgements| {
                                    references_from_value(&fields[8], false).and_then(|pending_owners| {
                                        references_from_value(&fields[9], false).and_then(|failed_owners| {
                                            inventories_from_value(&fields[10]).and_then(|inventories| {
                                                unsigned(&fields[11])
                                                    .and_then(ErasureReplayClaimV1::from_code)
                                                    .and_then(|replay_claim| {
                                                        receipt_proof(&fields[12..]).and_then(
                                                            |(policy, trust, provenance, issue_position, receipt_digest, signature)| {
                                                                let receipt = ErasureReceiptInputV1 {
                                                                    request,
                                                                    terminal_state,
                                                                    lifecycle,
                                                                    freeze_position,
                                                                    acknowledgements,
                                                                    required_targets,
                                                                    pending_owners,
                                                                    failed_owners,
                                                                    inventories,
                                                                    replay_claim,
                                                                    policy,
                                                                    trust,
                                                                    provenance,
                                                                    issue_position,
                                                                    signature,
                                                                    receipt_digest,
                                                                };
                                                                ErasureReceiptV1::new(receipt).and_then(|expected| {
                                                                    if expected.receipt_digest() == receipt_digest {
                                                                        Ok(expected)
                                                                    } else {
                                                                        Err(ErasureErrorV1::ProvenanceMissing)
                                                                    }
                                                                })
                                                            },
                                                        )
                                                    })
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    })
            })
        })
    })
}
fn receipt_proof(
    fields: &[Value],
) -> Result<
    (
        ErasureReferenceV1,
        ErasureReferenceV1,
        ErasureReferenceV1,
        u64,
        ErasureReferenceV1,
        ErasureReferenceV1,
    ),
    ErasureErrorV1,
> {
    bytes32(&fields[0]).and_then(|policy| {
        bytes32(&fields[1]).and_then(|trust| {
            bytes32(&fields[2]).and_then(|provenance| {
                unsigned(&fields[3]).and_then(|issue_position| {
                    bytes32(&fields[4]).and_then(|receipt_digest| {
                        bytes32(&fields[5]).map(|signature| {
                            (policy, trust, provenance, issue_position, receipt_digest, signature)
                        })
                    })
                })
            })
        })
    })
}
fn acknowledgements_from_value(
    value: &Value,
) -> Result<Vec<ErasureAcknowledgementV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS)
        .and_then(|values| {
            values
                .iter()
                .map(|value| {
                    exact_array(value, 4).and_then(|fields| {
                        target_from_value(&fields[0]).and_then(|target| {
                            bytes32(&fields[1]).and_then(|owner| {
                                bytes32(&fields[2]).and_then(|evidence| {
                                    unsigned(&fields[3])
                                    .and_then(ErasureAcknowledgementOutcomeV1::from_code)
                                    .map(|outcome| ErasureAcknowledgementV1 {
                                        target,
                                        owner,
                                        evidence,
                                        outcome,
                                    })
                                })
                            })
                        })
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .and_then(|acknowledgements| {
            if strictly_increasing(&acknowledgements) {
                Ok(acknowledgements)
            } else {
                Err(ErasureErrorV1::ScopeInvalid)
            }
        })
}
fn target_value(target: ErasureRequiredTargetV1) -> Value {
    Value::Array(vec![
        uint(target.artifact_class.code()),
        digest(target.artifact_digest),
        uint(target.key_role.code()),
        digest(target.key_digest),
        digest(target.replica_set),
        digest(target.replica_id),
    ])
}
fn target_from_value(value: &Value) -> Result<ErasureRequiredTargetV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0])
            .and_then(ErasureArtifactClassV1::from_code)
            .and_then(|artifact_class| {
                bytes32(&fields[1]).and_then(|artifact_digest| {
                    unsigned(&fields[2])
                        .and_then(ErasureKeyRoleV1::from_code)
                        .and_then(|key_role| {
                            bytes32(&fields[3]).and_then(|key_digest| {
                                bytes32(&fields[4]).and_then(|replica_set| {
                                    bytes32(&fields[5]).map(|replica_id| ErasureRequiredTargetV1 {
                                        artifact_class,
                                        artifact_digest,
                                        key_role,
                                        key_digest,
                                        replica_set,
                                        replica_id,
                                    })
                                })
                            })
                        })
                })
            })
    })
}
fn targets_value(targets: &[ErasureRequiredTargetV1]) -> Value {
    Value::Array(targets.iter().copied().map(target_value).collect())
}
fn targets_from_value(value: &Value) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(target_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|targets| {
                if strictly_increasing(&targets) {
                    Ok(targets)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
fn transition_value(transition: ErasureArtifactTransitionV1) -> Value {
    Value::Array(vec![
        uint(transition.from.code()),
        uint(transition.to.code()),
        digest(transition.reason),
        digest(transition.owner),
        digest(transition.acknowledgements),
        digest(transition.provenance),
    ])
}
fn transition_from_value(value: &Value) -> Result<ErasureArtifactTransitionV1, ErasureErrorV1> {
    exact_array(value, 6).and_then(|fields| {
        unsigned(&fields[0])
            .and_then(ErasureReplayClaimV1::from_code)
            .and_then(|from| {
                unsigned(&fields[1])
                    .and_then(ErasureReplayClaimV1::from_code)
                    .and_then(|to| {
                        bytes32(&fields[2]).and_then(|reason| {
                            bytes32(&fields[3]).and_then(|owner| {
                                bytes32(&fields[4]).and_then(|acknowledgements| {
                                    bytes32(&fields[5]).map(|provenance| {
                                        ErasureArtifactTransitionV1 {
                                            from,
                                            to,
                                            reason,
                                            owner,
                                            acknowledgements,
                                            provenance,
                                        }
                                    })
                                })
                            })
                        })
                    })
            })
    })
}
fn inventory_result_value(result: &ErasureInventoryResultV1) -> Value {
    Value::Array(vec![
        target_value(result.target),
        transition_value(result.transition),
        digest(result.retained_disclosure),
    ])
}
fn inventory_result_from_value(value: &Value) -> Result<ErasureInventoryResultV1, ErasureErrorV1> {
    exact_array(value, 3).and_then(|fields| {
        target_from_value(&fields[0]).and_then(|target| {
            transition_from_value(&fields[1]).and_then(|transition| {
                bytes32(&fields[2]).map(|retained_disclosure| ErasureInventoryResultV1 {
                    target,
                    transition,
                    retained_disclosure,
                })
            })
        })
    })
}
fn inventory_value(inventory: &[ErasureInventoryResultV1]) -> Value {
    Value::Array(inventory.iter().map(inventory_result_value).collect())
}
fn inventory_from_value(value: &Value) -> Result<Vec<ErasureInventoryResultV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_INVENTORY_RESULTS).and_then(|values| {
        values
            .iter()
            .map(inventory_result_from_value)
            .collect::<Result<Vec<_>, _>>()
            .and_then(|results| {
                if strictly_increasing(&results) {
                    Ok(results)
                } else {
                    Err(ErasureErrorV1::ScopeInvalid)
                }
            })
    })
}
fn inventories_value(inventories: &ErasureReceiptInventoriesV1) -> Value {
    Value::Array(vec![
        inventory_value(&inventories.artifacts),
        inventory_value(&inventories.keys),
        inventory_value(&inventories.replicas),
        inventory_value(&inventories.backups),
    ])
}
fn inventories_from_value(value: &Value) -> Result<ErasureReceiptInventoriesV1, ErasureErrorV1> {
    exact_array(value, 4).and_then(|fields| {
        inventory_from_value(&fields[0]).and_then(|artifacts| {
            inventory_from_value(&fields[1]).and_then(|keys| {
                inventory_from_value(&fields[2]).and_then(|replicas| {
                    inventory_from_value(&fields[3]).map(|backups| ErasureReceiptInventoriesV1 {
                        artifacts,
                        keys,
                        replicas,
                        backups,
                    })
                })
            })
        })
    })
}
const fn inventories_exceed_bound(inventories: &ErasureReceiptInventoriesV1) -> bool {
    inventories.artifacts.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.keys.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.replicas.len() > ERASURE_MAX_INVENTORY_RESULTS
        || inventories.backups.len() > ERASURE_MAX_INVENTORY_RESULTS
}
fn sort_inventories(inventories: &mut ErasureReceiptInventoriesV1) {
    inventories.artifacts.sort_unstable();
    inventories.keys.sort_unstable();
    inventories.replicas.sort_unstable();
    inventories.backups.sort_unstable();
}
fn inventories_have_duplicate_targets(inventories: &ErasureReceiptInventoriesV1) -> bool {
    has_duplicate_by_inventory_target(&inventories.artifacts)
        || has_duplicate_by_inventory_target(&inventories.keys)
        || has_duplicate_by_inventory_target(&inventories.replicas)
        || has_duplicate_by_inventory_target(&inventories.backups)
}
fn has_duplicate_by_inventory_target(entries: &[ErasureInventoryResultV1]) -> bool {
    entries.windows(2).any(|pair| pair[0].target == pair[1].target)
}
fn inventory_transitions_preserve_or_weaken(inventories: &ErasureReceiptInventoriesV1) -> bool {
    [&inventories.artifacts, &inventories.keys, &inventories.replicas, &inventories.backups]
        .into_iter()
        .flatten()
        .all(|entry| entry.transition.from.preserves_or_weakens(entry.transition.to))
}
fn inventories_match_closure(
    required_targets: &[ErasureRequiredTargetV1],
    inventories: &ErasureReceiptInventoriesV1,
) -> bool {
    let mut targets = inventories
        .artifacts
        .iter()
        .chain(&inventories.keys)
        .chain(&inventories.replicas)
        .chain(&inventories.backups)
        .map(|entry| entry.target)
        .collect::<Vec<_>>();
    targets.sort_unstable();
    targets == required_targets
}
fn has_duplicate_by_target(acknowledgements: &[ErasureAcknowledgementV1]) -> bool {
    acknowledgements.windows(2).any(|pair| pair[0].target == pair[1].target)
}
fn acknowledgements_match_closure(
    required_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    required_targets.len() == acknowledgements.len()
        && required_targets
            .iter()
            .zip(acknowledgements)
            .all(|(target, acknowledgement)| target == &acknowledgement.target)
}
fn acknowledgements_are_closure_subset(
    required_targets: &[ErasureRequiredTargetV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    acknowledgements
        .iter()
        .all(|acknowledgement| required_targets.binary_search(&acknowledgement.target).is_ok())
}
fn references_value(references: &[ErasureReferenceV1]) -> Value {
    Value::Array(references.iter().copied().map(digest).collect())
}
fn references_from_value(
    value: &Value,
    required: bool,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    array(value, ERASURE_MAX_REFERENCES).and_then(|values| {
        if required && values.is_empty() {
            Err(ErasureErrorV1::ScopeInvalid)
        } else {
            values
                .iter()
                .map(bytes32)
                .collect::<Result<Vec<_>, _>>()
                .and_then(|references| {
                    if strictly_increasing(&references) {
                        Ok(references)
                    } else {
                        Err(ErasureErrorV1::ScopeInvalid)
                    }
                })
        }
    })
}
fn header(fields: &[Value], contract: &str) -> Result<(), ErasureErrorV1> {
    string(&fields[0]).and_then(|found_contract| {
        if found_contract == contract {
            unsigned(&fields[1]).and_then(|version| {
                if version == VERSION {
                    Ok(())
                } else {
                    Err(ErasureErrorV1::UnsupportedVersion)
                }
            })
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
fn invalid_owner_sets(pending: &[ErasureReferenceV1], failed: &[ErasureReferenceV1]) -> bool {
    pending.len() > ERASURE_MAX_REFERENCES
        || failed.len() > ERASURE_MAX_REFERENCES
        || !strictly_increasing(pending)
        || !strictly_increasing(failed)
        || pending
            .iter()
            .any(|reference| failed.binary_search(reference).is_ok())
}
fn has_duplicate<T: Eq>(values: &[T]) -> bool {
    values.windows(2).any(|pair| pair[0] == pair[1])
}
fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn freeze_is_monotonic(previous: Option<u64>, next: Option<u64>) -> bool {
    previous.is_none() || previous == next
}
const fn reference_zero() -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([0; 32])
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn digest(reference: ErasureReferenceV1) -> Value {
    Value::Bytes(reference.digest().to_vec())
}
fn optional_digest(reference: Option<ErasureReferenceV1>) -> Value {
    reference.map_or(Value::Null, digest)
}
fn optional_uint(value: Option<u64>) -> Value {
    value.map_or(Value::Null, uint)
}
fn encode_canonical(value: &Value) -> Result<Vec<u8>, ErasureErrorV1> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .map_err(|_| ErasureErrorV1::InvalidEncoding)
}
fn encode_limited(value: &Value, maximum: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    encode_canonical(value).and_then(|bytes| {
        if bytes.len() <= maximum {
            Ok(bytes)
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    })
}
fn decode_limited(bytes: &[u8], maximum: usize) -> Result<Value, ErasureErrorV1> {
    if bytes.len() > maximum {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    cbor_shape_is_bounded(bytes).and_then(|()| {
        let mut cursor = Cursor::new(bytes);
        match ciborium::from_reader(&mut cursor) {
            Ok(value) => {
                if cursor.position() != bytes.len() as u64 {
                    return Err(ErasureErrorV1::InvalidEncoding);
                }
                encode_canonical(&value).and_then(|canonical| {
                    if canonical == bytes {
                        Ok(value)
                    } else {
                        Err(ErasureErrorV1::InvalidEncoding)
                    }
                })
            }
            Err(_) => Err(ErasureErrorV1::InvalidEncoding),
        }
    })
}
fn cbor_shape_is_bounded(bytes: &[u8]) -> Result<(), ErasureErrorV1> {
    cbor_item_end(bytes, 0, 0).and_then(|end| {
        if end == bytes.len() {
            Ok(())
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
fn cbor_item_end(bytes: &[u8], offset: usize, depth: usize) -> Result<usize, ErasureErrorV1> {
    if depth > 16 || offset >= bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let initial = bytes[offset];
    let major = initial >> 5;
    cbor_argument(bytes, offset + 1, initial & 0x1f).and_then(|(argument, next)| match major {
        0 | 1 => Ok(next),
        2 | 3 => match usize::try_from(argument) {
            Ok(length) if length <= bytes.len().saturating_sub(next) => Ok(next + length),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        },
        4 if argument <= ERASURE_MAX_INVENTORY_RESULTS as u64 => {
            cbor_array_end(bytes, next, depth + 1, argument)
        }
        7 if argument <= 22 => Ok(next),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    })
}
fn cbor_array_end(
    bytes: &[u8],
    mut offset: usize,
    depth: usize,
    count: u64,
) -> Result<usize, ErasureErrorV1> {
    for _ in 0..count {
        let Ok(next) = cbor_item_end(bytes, offset, depth) else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        offset = next;
    }
    Ok(offset)
}
fn cbor_argument(
    bytes: &[u8],
    offset: usize,
    additional: u8,
) -> Result<(u64, usize), ErasureErrorV1> {
    match additional {
        0..=23 => Ok((u64::from(additional), offset)),
        24 => cbor_argument_bytes(bytes, offset, 1, 24),
        25 => cbor_argument_bytes(bytes, offset, 2, 256),
        26 => cbor_argument_bytes(bytes, offset, 4, 65_536),
        27 => cbor_argument_bytes(bytes, offset, 8, 4_294_967_296),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
fn cbor_argument_bytes(
    bytes: &[u8],
    offset: usize,
    width: usize,
    minimum: u64,
) -> Result<(u64, usize), ErasureErrorV1> {
    let end = offset.saturating_add(width);
    if end > bytes.len() {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let value = bytes[offset..end]
        .iter()
        .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
    if value < minimum {
        Err(ErasureErrorV1::InvalidEncoding)
    } else {
        Ok((value, end))
    }
}
fn array(value: &Value, maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    match value {
        Value::Array(values) if values.len() <= maximum => Ok(values),
        Value::Array(_) => Err(ErasureErrorV1::ScopeInvalid),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
fn exact_array(value: &Value, expected: usize) -> Result<&[Value], ErasureErrorV1> {
    array(value, expected).and_then(|values| {
        if values.len() == expected {
            Ok(values)
        } else {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    })
}
fn string(value: &Value) -> Result<&str, ErasureErrorV1> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
fn unsigned(value: &Value) -> Result<u64, ErasureErrorV1> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
fn optional_unsigned(value: &Value) -> Result<Option<u64>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        unsigned(value).map(Some)
    }
}
fn bytes32(value: &Value) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map(ErasureReferenceV1::from_digest)
            .map_err(|_| ErasureErrorV1::InvalidEncoding),
        _ => Err(ErasureErrorV1::InvalidEncoding),
    }
}
fn optional_bytes32(value: &Value) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes32(value).map(Some)
    }
}
fn domain_digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct TestCoordinatorPort {
        accepted: bool,
        targets: Vec<ErasureRequiredTargetV1>,
    }
    struct TestResolver {
        states: Vec<ErasureStateV1>,
        unavailable: bool,
    }
    impl ErasureStateResolverV1 for TestResolver {
        fn resolve_state(
            &self,
            digest: ErasureReferenceV1,
        ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
            if self.unavailable {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            Ok(self
                .states
                .iter()
                .find(|state| state.state_digest() == digest)
                .cloned())
        }
    }
    impl ErasureCoordinatorPortV1 for TestCoordinatorPort {
        fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
            if self.accepted { Ok(()) } else { Err(ErasureErrorV1::Unauthorized) }
        }
        fn required_targets(&self, _request: ErasureReferenceV1) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
            Ok(self.targets.clone())
        }
    }
    fn reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }
    fn indexed_reference(index: usize) -> ErasureReferenceV1 {
        let mut digest = [0; 32];
        let index = index.to_be_bytes();
        digest[32 - index.len()..].copy_from_slice(&index);
        ErasureReferenceV1::from_digest(digest)
    }
    fn references(count: usize) -> Vec<ErasureReferenceV1> {
        (0..count).map(indexed_reference).collect()
    }
    fn request_input(selectors: Vec<ErasureReferenceV1>) -> ErasureRequestInputV1 {
        ErasureRequestInputV1 {
            request: reference(1),
            subject: reference(2),
            scope: ErasureScopeV1::PrivateSubjectData,
            selectors,
            requester: reference(3),
            authorization: reference(4),
            policy: reference(5),
            request_position: 9,
            horizon_position: 10,
            provenance: reference(6),
        }
    }
    fn request() -> Result<ErasureRequestV1, ErasureErrorV1> {
        ErasureRequestV1::new(request_input(vec![reference(8), reference(7)]))
    }
    fn change(
        lifecycle: ErasureLifecycleV1,
        freeze_position: Option<u64>,
        pending_owners: Vec<ErasureReferenceV1>,
        failed_owners: Vec<ErasureReferenceV1>,
    ) -> ErasureStateTransitionV1 {
        ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners,
            failed_owners,
            replay_claim: ErasureReplayClaimV1::StructuralOnly,
            provenance: reference(9),
        }
    }
    fn acknowledgement(
        owner: u8,
        outcome: ErasureAcknowledgementOutcomeV1,
    ) -> ErasureAcknowledgementV1 {
        ErasureAcknowledgementV1 {
            target: ErasureRequiredTargetV1 {
                artifact_class: ErasureArtifactClassV1::TimelineReplay,
                artifact_digest: reference(owner),
                key_role: ErasureKeyRoleV1::DataEncryption,
                key_digest: reference(owner + 10),
                replica_set: reference(owner + 30),
                replica_id: reference(owner + 40),
            },
            owner: reference(owner),
            evidence: reference(owner + 20),
            outcome,
        }
    }
    fn inventory_result(target: ErasureRequiredTargetV1) -> ErasureInventoryResultV1 {
        ErasureInventoryResultV1 {
            target,
            transition: ErasureArtifactTransitionV1 {
                from: ErasureReplayClaimV1::Exact,
                to: ErasureReplayClaimV1::StructuralOnly,
                reason: reference(50),
                owner: reference(51),
                acknowledgements: reference(52),
                provenance: reference(53),
            },
            retained_disclosure: reference(54),
        }
    }
    fn receipt_input(
        lifecycle: ErasureLifecycleV1,
        acknowledgements: Vec<ErasureAcknowledgementV1>,
        pending_owners: Vec<ErasureReferenceV1>,
        failed_owners: Vec<ErasureReferenceV1>,
    ) -> ErasureReceiptInputV1 {
        let required_targets = acknowledgements
            .iter()
            .map(|acknowledgement| acknowledgement.target)
            .collect();
        let artifacts = acknowledgements
            .iter()
            .map(|acknowledgement| inventory_result(acknowledgement.target))
            .collect();
        ErasureReceiptInputV1 {
            request: reference(1),
            terminal_state: reference(6),
            lifecycle,
            freeze_position: 10,
            required_targets,
            acknowledgements,
            pending_owners,
            failed_owners,
            inventories: ErasureReceiptInventoriesV1 {
                artifacts,
                keys: Vec::new(),
                replicas: Vec::new(),
                backups: Vec::new(),
            },
            replay_claim: ErasureReplayClaimV1::StructuralOnly,
            policy: reference(2),
            trust: reference(3),
            provenance: reference(4),
            issue_position: 11,
            signature: reference(5),
            receipt_digest: reference_zero(),
        }
    }
    fn receipt() -> Result<ErasureReceiptV1, ErasureErrorV1> {
        ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![
                acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
                acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
            ],
            Vec::new(),
            Vec::new(),
        ))
    }
    fn dispatched() -> Result<ErasureStateV1, ErasureErrorV1> {
        ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
            .transition(change(
                ErasureLifecycleV1::Authorized,
                None,
                Vec::new(),
                Vec::new(),
            ))?
            .transition(change(
                ErasureLifecycleV1::AccessFrozen,
                Some(10),
                Vec::new(),
                Vec::new(),
            ))?
            .transition(change(
                ErasureLifecycleV1::DestructionDispatched,
                Some(10),
                Vec::new(),
                Vec::new(),
            ))
    }
    fn decode_request(value: &Value) -> Result<ErasureRequestV1, ErasureErrorV1> {
        ErasureRequestV1::from_canonical_cbor(&encode_canonical(value)?)
    }
    fn decode_state(value: &Value) -> Result<ErasureStateV1, ErasureErrorV1> {
        ErasureStateV1::from_canonical_cbor(&encode_canonical(value)?)
    }
    fn decode_receipt(value: &Value) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        ErasureReceiptV1::from_canonical_cbor(&encode_canonical(value)?)
    }
    #[test]
    fn coordinator_public_retries_reject_injection_and_query_existing() -> Result<(), ErasureErrorV1> {
        let acknowledgement = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let port = TestCoordinatorPort { accepted: true, targets: vec![acknowledgement.target] };
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        let submitted = coordinator.submit(request()?, reference(3))?;
        assert_eq!(coordinator.submit(request()?, reference(3))?, submitted);
        assert_eq!(coordinator.existing(reference(1)), Some(&submitted));
        Ok(())
    }
    #[test]
    fn coordinator_freezes_closure_and_commits_only_derived_terminal_outcomes() -> Result<(), ErasureErrorV1> {
        let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let port = TestCoordinatorPort { accepted: true, targets: vec![ack.target] };
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        coordinator.submit(request()?, reference(3))?;
        coordinator.advance(reference(1), change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new()))?;
        let frozen = coordinator.freeze_inventory(reference(1), change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new()))?;
        assert_eq!(coordinator.freeze_inventory(reference(1), change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new()))?, frozen);
        coordinator.advance(reference(1), change(ErasureLifecycleV1::DestructionDispatched, Some(10), Vec::new(), Vec::new()))?;
        assert_eq!(coordinator.acknowledge(reference(1), ack)?, coordinator.acknowledge(reference(1), ack)?);
        let injected = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
        assert_eq!(coordinator.acknowledge(reference(1), injected), Err(ErasureErrorV1::Unauthorized));
        let mut conflicting = ack;
        conflicting.outcome = ErasureAcknowledgementOutcomeV1::Negative;
        assert_eq!(coordinator.acknowledge(reference(1), conflicting), Err(ErasureErrorV1::PolicyConflict));
        let mut complete_input = receipt_input(ErasureLifecycleV1::PartialFailure, Vec::new(), vec![reference(9)], Vec::new());
        complete_input.inventories.artifacts = vec![inventory_result(ack.target)];
        let committed = coordinator.finalize(reference(1), complete_input.clone())?;
        assert_eq!(committed.lifecycle(), ErasureLifecycleV1::Complete);
        assert_eq!(coordinator.finalize(reference(1), complete_input)?, committed);
        assert_eq!(coordinator.existing(reference(1)).map(ErasureStateV1::lifecycle), Some(ErasureLifecycleV1::Complete));
        Ok(())
    }
    #[test]
    fn coordinator_derives_partial_failure_for_a_missing_frozen_target() -> Result<(), ErasureErrorV1> {
        let missing = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let port = TestCoordinatorPort { accepted: true, targets: vec![missing.target] };
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        coordinator.submit(request()?, reference(3))?;
        coordinator.advance(reference(1), change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new()))?;
        coordinator.freeze_inventory(reference(1), change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new()))?;
        coordinator.advance(reference(1), change(ErasureLifecycleV1::DestructionDispatched, Some(10), Vec::new(), Vec::new()))?;
        coordinator.advance(reference(1), change(ErasureLifecycleV1::AwaitingAcknowledgements, Some(10), Vec::new(), Vec::new()))?;
        let mut input = receipt_input(ErasureLifecycleV1::Complete, Vec::new(), Vec::new(), Vec::new());
        input.inventories.artifacts = vec![inventory_result(missing.target)];
        assert_eq!(coordinator.finalize(reference(1), input)?.lifecycle(), ErasureLifecycleV1::PartialFailure);
        Ok(())
    }
    #[test]
    fn coordinator_rejects_unauthenticated_submission_and_unsupported_version() -> Result<(), ErasureErrorV1> {
        let port = TestCoordinatorPort { accepted: false, targets: Vec::new() };
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        assert_eq!(coordinator.submit(request()?, reference(3)), Err(ErasureErrorV1::Unauthorized));
        let mut value = receipt_value(&receipt()?.0);
        let Value::Array(fields) = &mut value else { return Err(ErasureErrorV1::InvalidEncoding); };
        fields[1] = uint(2);
        assert_eq!(decode_receipt(&value), Err(ErasureErrorV1::UnsupportedVersion));
        Ok(())
    }
    #[test]
    fn receipt_history_requires_a_resolved_monotonic_terminal_chain() -> Result<(), ErasureErrorV1> {
        let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        let authorized = submitted.transition(change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new()))?;
        let frozen = authorized.transition(change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new()))?;
        let dispatched = frozen.transition(change(ErasureLifecycleV1::DestructionDispatched, Some(10), Vec::new(), Vec::new()))?;
        let waiting = dispatched.transition(change(ErasureLifecycleV1::AwaitingAcknowledgements, Some(10), Vec::new(), Vec::new()))?;
        let terminal = waiting.transition(change(ErasureLifecycleV1::Complete, Some(10), Vec::new(), Vec::new()))?;
        let mut input = receipt_input(ErasureLifecycleV1::Complete, vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged)], Vec::new(), Vec::new());
        input.terminal_state = terminal.state_digest();
        let receipt = ErasureReceiptV1::new(input)?;
        let resolver = TestResolver { states: vec![submitted, authorized, frozen, dispatched, waiting, terminal], unavailable: false };
        receipt.verify_history(&resolver)?;
        assert_eq!(receipt.verify_history(&TestResolver { states: Vec::new(), unavailable: false }), Err(ErasureErrorV1::ProvenanceMissing));
        assert_eq!(receipt.verify_history(&TestResolver { states: Vec::new(), unavailable: true }), Err(ErasureErrorV1::ProvenanceMissing));
        Ok(())
    }
    #[test]
    fn receipt_inventory_codes_and_strict_decoder_paths_are_publicly_exercised() -> Result<(), ErasureErrorV1> {
        let mut acknowledgements = vec![
            acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(3, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(4, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(5, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(6, ErasureAcknowledgementOutcomeV1::Acknowledged),
            acknowledgement(7, ErasureAcknowledgementOutcomeV1::Acknowledged),
        ];
        acknowledgements[1].target.artifact_class = ErasureArtifactClassV1::ReproManifest;
        acknowledgements[1].target.key_role = ErasureKeyRoleV1::Signing;
        acknowledgements[2].target.artifact_class = ErasureArtifactClassV1::CausalTrace;
        acknowledgements[2].target.key_role = ErasureKeyRoleV1::BackupEnvelope;
        acknowledgements[3].target.artifact_class = ErasureArtifactClassV1::ConformanceReport;
        acknowledgements[3].target.key_role = ErasureKeyRoleV1::ReplicaTransport;
        acknowledgements[4].target.artifact_class = ErasureArtifactClassV1::CalibrationReport;
        acknowledgements[5].target.artifact_class = ErasureArtifactClassV1::Export;
        acknowledgements[6].target.artifact_class = ErasureArtifactClassV1::ForkOrSnapshot;
        let mut input = receipt_input(ErasureLifecycleV1::Complete, acknowledgements.clone(), Vec::new(), Vec::new());
        input.inventories.artifacts = vec![
            inventory_result(acknowledgements[0].target),
            inventory_result(acknowledgements[4].target),
            inventory_result(acknowledgements[5].target),
            inventory_result(acknowledgements[6].target),
        ];
        input.inventories.keys = vec![inventory_result(acknowledgements[1].target)];
        input.inventories.replicas = vec![inventory_result(acknowledgements[2].target)];
        input.inventories.backups = vec![inventory_result(acknowledgements[3].target)];
        let encoded = ErasureReceiptV1::new(input)?.to_canonical_cbor()?;
        assert_eq!(ErasureReceiptV1::from_canonical_cbor(&encoded)?.to_canonical_cbor()?, encoded);
        let mut unknown_codes = receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?.0);
        let mut tampered_digest = unknown_codes.clone();
        let Value::Array(fields) = &mut tampered_digest else { return Err(ErasureErrorV1::InvalidEncoding); };
        fields[16] = digest(reference(99));
        assert_eq!(decode_receipt(&tampered_digest), Err(ErasureErrorV1::ProvenanceMissing));
        let Value::Array(fields) = &mut unknown_codes else { return Err(ErasureErrorV1::InvalidEncoding); };
        let Value::Array(targets) = &mut fields[6] else { return Err(ErasureErrorV1::InvalidEncoding); };
        let Value::Array(target) = &mut targets[0] else { return Err(ErasureErrorV1::InvalidEncoding); };
        target[0] = uint(7);
        assert_eq!(decode_receipt(&unknown_codes), Err(ErasureErrorV1::InvalidEncoding));
        let mut unknown_role = receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?.0);
        let Value::Array(fields) = &mut unknown_role else { return Err(ErasureErrorV1::InvalidEncoding); };
        let Value::Array(targets) = &mut fields[6] else { return Err(ErasureErrorV1::InvalidEncoding); };
        let Value::Array(target) = &mut targets[0] else { return Err(ErasureErrorV1::InvalidEncoding); };
        target[2] = uint(4);
        assert_eq!(decode_receipt(&unknown_role), Err(ErasureErrorV1::InvalidEncoding));
        let mut unordered_targets = receipt_value(&ErasureReceiptV1::from_canonical_cbor(&encoded)?.0);
        let Value::Array(fields) = &mut unordered_targets else { return Err(ErasureErrorV1::InvalidEncoding); };
        let Value::Array(targets) = &mut fields[6] else { return Err(ErasureErrorV1::InvalidEncoding); };
        targets.swap(0, 1);
        assert_eq!(decode_receipt(&unordered_targets), Err(ErasureErrorV1::ScopeInvalid));
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(ErasureReceiptV1::from_canonical_cbor(&trailing), Err(ErasureErrorV1::InvalidEncoding));
        let noncanonical = [&[0x98, 18][..], &encoded[1..]].concat();
        assert_eq!(ErasureReceiptV1::from_canonical_cbor(&noncanonical), Err(ErasureErrorV1::InvalidEncoding));
        for invalid in [&[0x9f, 0xff][..], &[0xbf, 0xff][..], &[0x19, 0, 1][..], &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..], &[0x9a, 0xff, 0xff, 0xff, 0xff][..], &[0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00][..]] {
            assert_eq!(ErasureReceiptV1::from_canonical_cbor(invalid), Err(ErasureErrorV1::InvalidEncoding));
        }
        Ok(())
    }
    #[test]
    fn coordinator_and_receipt_reject_each_public_injected_or_stale_seam() -> Result<(), ErasureErrorV1> {
        let ack = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let port = TestCoordinatorPort { accepted: true, targets: vec![ack.target] };
        let mut coordinator = ErasureCoordinatorStateMachineV1::new(port, reference(2));
        coordinator.submit(request()?, reference(3))?;
        assert_eq!(coordinator.advance(reference(1), change(ErasureLifecycleV1::Submitted, None, Vec::new(), Vec::new()))?.lifecycle(), ErasureLifecycleV1::Submitted);
        assert_eq!(coordinator.advance(reference(1), change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new())), Err(ErasureErrorV1::PolicyConflict));
        assert_eq!(coordinator.freeze_inventory(reference(1), change(ErasureLifecycleV1::AccessFrozen, Some(10), Vec::new(), Vec::new())), Err(ErasureErrorV1::PolicyConflict));
        assert_eq!(coordinator.acknowledge(reference(1), ack), Err(ErasureErrorV1::PolicyConflict));
        assert_eq!(coordinator.finalize(reference(1), receipt_input(ErasureLifecycleV1::Complete, vec![ack], Vec::new(), Vec::new())), Err(ErasureErrorV1::PolicyConflict));
        let mut stale_issue = receipt_input(ErasureLifecycleV1::Complete, vec![ack], Vec::new(), Vec::new());
        stale_issue.issue_position = 9;
        assert_eq!(ErasureReceiptV1::new(stale_issue), Err(ErasureErrorV1::PolicyConflict));
        let mut invented_ack = receipt_input(ErasureLifecycleV1::Complete, vec![ack], Vec::new(), Vec::new());
        invented_ack.acknowledgements[0].target = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
        assert_eq!(ErasureReceiptV1::new(invented_ack), Err(ErasureErrorV1::ScopeInvalid));
        let mut missing_inventory = receipt_input(ErasureLifecycleV1::Complete, vec![ack], Vec::new(), Vec::new());
        missing_inventory.inventories.artifacts.clear();
        assert_eq!(ErasureReceiptV1::new(missing_inventory), Err(ErasureErrorV1::ScopeInvalid));
        let mut oversized = receipt_input(ErasureLifecycleV1::PartialFailure, Vec::new(), vec![reference(8)], Vec::new());
        oversized.acknowledgements = vec![ack; ERASURE_MAX_INVENTORY_RESULTS + 1];
        assert_eq!(ErasureReceiptV1::new(oversized), Err(ErasureErrorV1::ScopeInvalid));
        let mut strengthened = receipt_input(ErasureLifecycleV1::Complete, vec![ack], Vec::new(), Vec::new());
        strengthened.inventories.artifacts[0].transition.from = ErasureReplayClaimV1::StructuralOnly;
        strengthened.inventories.artifacts[0].transition.to = ErasureReplayClaimV1::Exact;
        assert_eq!(ErasureReceiptV1::new(strengthened), Err(ErasureErrorV1::PolicyConflict));
        for invalid in [&[0x18, 0][..], &[0x1a, 0, 0, 0, 1][..], &[0x60, 0][..]] {
            assert_eq!(ErasureReceiptV1::from_canonical_cbor(invalid), Err(ErasureErrorV1::InvalidEncoding));
        }
        Ok(())
    }
    #[test]
    fn request_is_canonical_and_bounded() -> Result<(), ErasureErrorV1> {
        let first = request()?;
        let second = ErasureRequestV1::new(request_input(vec![reference(7), reference(8)]))?;
        let bytes = first.to_canonical_cbor()?;
        assert_eq!(bytes, second.to_canonical_cbor()?);
        assert_eq!(ErasureRequestV1::from_canonical_cbor(&bytes)?, first);
        assert_eq!(first.reference(), reference(1));
        assert_eq!(
            ErasureRequestV1::new(request_input(Vec::new())),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::new(request_input(vec![reference(7), reference(7)])),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        let mut impossible = request_input(vec![reference(7)]);
        impossible.request_position = 11;
        assert_eq!(
            ErasureRequestV1::new(impossible),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }
    #[test]
    fn public_constants_display_and_state_digests_are_observable() -> Result<(), ErasureErrorV1> {
        assert_eq!(ERASURE_REQUEST_OR_STATE_MAX_BYTES, 1_048_576);
        assert_eq!(ERASURE_RECEIPT_MAX_BYTES, 16_777_216);
        assert_eq!(
            ErasureErrorV1::PolicyConflict.to_string(),
            "erasure contract error 4"
        );
        let first = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        let second = ErasureStateV1::submitted(reference(4), reference(2), reference(3))?;
        assert_ne!(first.state_digest(), second.state_digest());
        Ok(())
    }
    #[test]
    fn codecs_refuse_trailing_unknown_and_maps() -> Result<(), ErasureErrorV1> {
        let mut trailing = request()?.to_canonical_cbor()?;
        trailing.push(0);
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&trailing),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let mut unsupported = request_value(&request()?.0);
        let Value::Array(fields) = &mut unsupported else {
            return Err(ErasureErrorV1::InvalidEncoding);
        };
        fields[1] = uint(2);
        let mut bytes = Vec::new();
        ciborium::into_writer(&unsupported, &mut bytes)
            .map_err(|_| ErasureErrorV1::InvalidEncoding)?;
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&bytes),
            Err(ErasureErrorV1::UnsupportedVersion)
        );
        let map = Value::Map(vec![(text("request"), digest(reference(1)))]);
        let mut map_bytes = Vec::new();
        ciborium::into_writer(&map, &mut map_bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&map_bytes),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }
    #[test]
    fn decoders_refuse_unknown_closed_codes() -> Result<(), ErasureErrorV1> {
        let mut invalid_scope = request_value(&request()?.0);
        {
            let Value::Array(fields) = &mut invalid_scope else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[4] = uint(5);
        }
        assert_eq!(
            decode_request(&invalid_scope),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        let mut invalid_lifecycle = state_value(&submitted);
        {
            let Value::Array(fields) = &mut invalid_lifecycle else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[3] = uint(8);
        }
        assert_eq!(
            decode_state(&invalid_lifecycle),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let mut invalid_claim = state_value(&submitted);
        {
            let Value::Array(fields) = &mut invalid_claim else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[8] = uint(5);
        }
        assert_eq!(
            decode_state(&invalid_claim),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let canonical = receipt()?;
        let mut invalid_outcome = receipt_value(&canonical.0);
        {
            let Value::Array(fields) = &mut invalid_outcome else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            let Value::Array(acknowledgements) = &mut fields[7] else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            let Value::Array(acknowledgement) = &mut acknowledgements[0] else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            acknowledgement[3] = uint(3);
        }
        assert_eq!(
            decode_receipt(&invalid_outcome),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }
    #[test]
    fn request_decoder_refuses_noncanonical_and_wrong_shapes() -> Result<(), ErasureErrorV1> {
        let mut wrong_tag_type = request_value(&request()?.0);
        {
            let Value::Array(fields) = &mut wrong_tag_type else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[0] = Value::Bool(false);
        }
        assert_eq!(
            decode_request(&wrong_tag_type),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let mut wrong_scope_type = request_value(&request()?.0);
        {
            let Value::Array(fields) = &mut wrong_scope_type else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[4] = Value::Bool(false);
        }
        assert_eq!(
            decode_request(&wrong_scope_type),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let mut empty_selectors = request_value(&request()?.0);
        {
            let Value::Array(fields) = &mut empty_selectors else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[5] = Value::Array(Vec::new());
        }
        assert_eq!(
            decode_request(&empty_selectors),
            Err(ErasureErrorV1::ScopeInvalid)
        );

        assert_eq!(
            decode_request(&Value::Array(vec![Value::Null; 13])),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            decode_request(&Value::Null),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert_eq!(
            decode_request(&Value::Array(Vec::new())),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let canonical = request()?.to_canonical_cbor()?;
        let noncanonical = [&[0x98, 12][..], &canonical[1..]].concat();
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&noncanonical),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }
    #[test]
    fn receipt_decoder_refuses_unsorted_acknowledgements() -> Result<(), ErasureErrorV1> {
        let canonical = receipt()?;
        let mut unsorted = receipt_value(&canonical.0);
        {
            let Value::Array(fields) = &mut unsorted else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            let Value::Array(acknowledgements) = &mut fields[7] else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            acknowledgements.swap(0, 1);
        }
        assert_eq!(decode_receipt(&unsorted), Err(ErasureErrorV1::ScopeInvalid));
        Ok(())
    }
    #[test]
    fn receipt_constructor_bounds_acknowledgements() {
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::PartialFailure,
                vec![
                    acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative);
                    ERASURE_MAX_REFERENCES + 1
                ],
                Vec::new(),
                Vec::new(),
            )),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
    #[test]
    fn lifecycle_public_edges_and_terminality_are_closed() {
        assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
        assert!(ErasureLifecycleV1::Authorized.permits(ErasureLifecycleV1::AccessFrozen));
        assert!(ErasureLifecycleV1::AccessFrozen.permits(ErasureLifecycleV1::DestructionDispatched));
        assert!(ErasureLifecycleV1::DestructionDispatched
            .permits(ErasureLifecycleV1::AwaitingAcknowledgements));
        assert!(ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::Complete));
        assert!(ErasureLifecycleV1::AwaitingAcknowledgements
            .permits(ErasureLifecycleV1::PartialFailure));
        assert!(!ErasureLifecycleV1::Rejected.permits(ErasureLifecycleV1::Submitted));
        assert!(ErasureLifecycleV1::Complete.is_terminal());
        assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
        assert!(ErasureLifecycleV1::Rejected.is_terminal());
        assert!(!ErasureLifecycleV1::Authorized.is_terminal());
    }
    #[test]
    fn lifecycle_is_monotonic_and_digest_linked() -> Result<(), ErasureErrorV1> {
        let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        assert!(submitted
            .lifecycle()
            .permits(ErasureLifecycleV1::Authorized));
        assert!(submitted.lifecycle().permits(ErasureLifecycleV1::Rejected));
        assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::Authorized));
        assert!(ErasureLifecycleV1::PartialFailure.is_terminal());
        assert_eq!(
            submitted.transition(change(
                ErasureLifecycleV1::Submitted,
                None,
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert_eq!(
            submitted.transition(change(
                ErasureLifecycleV1::Rejected,
                None,
                vec![reference(7)],
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let authorized = submitted.transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?;
        assert_eq!(
            authorized.transition(change(
                ErasureLifecycleV1::AccessFrozen,
                None,
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let frozen = authorized.transition(change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        assert_eq!(
            frozen.transition(change(
                ErasureLifecycleV1::DestructionDispatched,
                Some(11),
                Vec::new(),
                Vec::new(),
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let dispatched = frozen.transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        let waiting = dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            vec![reference(7)],
            Vec::new(),
        ))?;
        assert_eq!(
            waiting.transition(change(
                ErasureLifecycleV1::Complete,
                Some(10),
                vec![reference(7)],
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let partial = waiting.transition(change(
            ErasureLifecycleV1::PartialFailure,
            Some(10),
            Vec::new(),
            vec![reference(7)],
        ))?;
        let bytes = partial.to_canonical_cbor()?;
        assert_eq!(ErasureStateV1::from_canonical_cbor(&bytes)?, partial);
        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&tampered),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }
    #[test]
    fn owner_evidence_bounds_are_enforced_at_the_public_transition() -> Result<(), ErasureErrorV1> {
        let dispatched = dispatched()?;
        assert!(dispatched
            .transition(change(
                ErasureLifecycleV1::AwaitingAcknowledgements,
                Some(10),
                references(ERASURE_MAX_REFERENCES),
                Vec::new(),
            ))
            .is_ok());
        assert!(dispatched
            .transition(change(
                ErasureLifecycleV1::AwaitingAcknowledgements,
                Some(10),
                Vec::new(),
                references(ERASURE_MAX_REFERENCES),
            ))
            .is_ok());
        assert_eq!(
            dispatched.transition(change(
                ErasureLifecycleV1::AwaitingAcknowledgements,
                Some(10),
                references(ERASURE_MAX_REFERENCES + 1),
                Vec::new(),
            )),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            dispatched.transition(change(
                ErasureLifecycleV1::AwaitingAcknowledgements,
                Some(10),
                Vec::new(),
                references(ERASURE_MAX_REFERENCES + 1),
            )),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }
    #[test]
    fn receipt_order_is_arrival_independent_and_completion_is_strict() -> Result<(), ErasureErrorV1>
    {
        let low = acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let high = acknowledgement(2, ErasureAcknowledgementOutcomeV1::Acknowledged);
        let first = ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![high, low],
            Vec::new(),
            Vec::new(),
        ))?;
        let second = ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::Complete,
            vec![low, high],
            Vec::new(),
            Vec::new(),
        ))?;
        let bytes = first.to_canonical_cbor()?;
        assert_eq!(bytes, second.to_canonical_cbor()?);
        assert_eq!(ErasureReceiptV1::from_canonical_cbor(&bytes)?, first);
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::Complete,
                vec![acknowledgement(
                    3,
                    ErasureAcknowledgementOutcomeV1::Negative
                )],
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::PartialFailure,
                vec![low],
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert!(ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![low],
            vec![reference(9)],
            Vec::new()
        ))
        .is_ok());
        Ok(())
    }
    #[test]
    fn safe_errors_are_closed_and_payload_free() {
        for code in 0..16 {
            assert_eq!(
                ErasureErrorV1::from_code(code).map(ErasureErrorV1::code),
                Ok(code)
            );
        }
        assert_eq!(
            ErasureErrorV1::from_code(16),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        assert!(!ErasureErrorV1::ArtifactDeletionFailed
            .to_string()
            .contains("payload"));
    }

    #[test]
    fn every_closed_wire_enum_round_trips_at_its_public_seam() -> Result<(), ErasureErrorV1> {
        for scope in [
            ErasureScopeV1::PrivateSubjectData,
            ErasureScopeV1::ConsentedSharedData,
            ErasureScopeV1::PublicRecord,
            ErasureScopeV1::Aggregate,
            ErasureScopeV1::StructuralAuditMetadata,
        ] {
            let mut input = request_input(vec![reference(7)]);
            input.scope = scope;
            let request = ErasureRequestV1::new(input)?;
            assert_eq!(
                ErasureRequestV1::from_canonical_cbor(&request.to_canonical_cbor()?)?,
                request
            );
        }

        let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        let authorized = submitted.transition(change(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
        ))?;
        let frozen = authorized.transition(change(
            ErasureLifecycleV1::AccessFrozen,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        let dispatched = frozen.transition(change(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        let waiting = dispatched.transition(change(
            ErasureLifecycleV1::AwaitingAcknowledgements,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        let complete = waiting.transition(change(
            ErasureLifecycleV1::Complete,
            Some(10),
            Vec::new(),
            Vec::new(),
        ))?;
        let rejected = submitted.transition(change(
            ErasureLifecycleV1::Rejected,
            None,
            Vec::new(),
            Vec::new(),
        ))?;
        for state in [
            submitted, authorized, frozen, dispatched, waiting, complete, rejected,
        ] {
            assert_eq!(
                ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
                state
            );
            assert_ne!(state.state_digest(), reference_zero());
        }

        for claim in [
            ErasureReplayClaimV1::Exact,
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ErasureReplayClaimV1::StructuralOnly,
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            ErasureReplayClaimV1::IncompatibleProfile,
        ] {
            let mut transition =
                change(ErasureLifecycleV1::Authorized, None, Vec::new(), Vec::new());
            transition.replay_claim = claim;
            let state = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?
                .transition(transition)?;
            assert_eq!(
                ErasureStateV1::from_canonical_cbor(&state.to_canonical_cbor()?)?,
                state
            );
        }

        let receipt = ErasureReceiptV1::new(receipt_input(
            ErasureLifecycleV1::PartialFailure,
            vec![
                acknowledgement(1, ErasureAcknowledgementOutcomeV1::Negative),
                acknowledgement(2, ErasureAcknowledgementOutcomeV1::Stale),
            ],
            Vec::new(),
            vec![reference(9)],
        ))?;
        assert_eq!(
            ErasureReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor()?)?,
            receipt
        );
        Ok(())
    }

    #[test]
    fn request_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
        let request = request()?;
        let mut malformed = request_value(&request.0);
        {
            let Value::Array(fields) = &mut malformed else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[0] = text("other-contract");
        }
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&encode_canonical(&malformed)?),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        {
            let Value::Array(fields) = &mut malformed else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[0] = text(ERQ1);
            fields[2] = Value::Bool(false);
        }
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&encode_canonical(&malformed)?),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        {
            let Value::Array(fields) = &mut malformed else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            fields[2] = digest(reference(1));
            fields[5] = Value::Array(vec![digest(reference(9)), digest(reference(8))]);
        }
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&encode_canonical(&malformed)?),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::new(request_input(vec![
                reference(7);
                ERASURE_MAX_REFERENCES + 1
            ])),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES + 1]),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&vec![0; ERASURE_REQUEST_OR_STATE_MAX_BYTES]),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn state_decoder_rejects_retained_wire_boundaries() -> Result<(), ErasureErrorV1> {
        let submitted = ErasureStateV1::submitted(reference(1), reference(2), reference(3))?;
        assert_eq!(
            submitted.transition(change(
                ErasureLifecycleV1::Authorized,
                None,
                vec![reference(7), reference(7)],
                Vec::new()
            )),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        let mut invalid_state = state_value(&submitted);
        {
            let Value::Array(state_fields) = &mut invalid_state else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            state_fields[6] = Value::Array(vec![digest(reference(7)), digest(reference(7))]);
        }
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&encode_canonical(&invalid_state)?),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        {
            let Value::Array(state_fields) = &mut invalid_state else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            state_fields[6] = Value::Array(Vec::new());
            state_fields[9] = digest(reference(8));
        }
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&encode_canonical(&invalid_state)?),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        {
            let Value::Array(state_fields) = &mut invalid_state else {
                return Err(ErasureErrorV1::InvalidEncoding);
            };
            state_fields[3] = uint(ErasureLifecycleV1::PartialFailure.code());
            state_fields[4] = uint(10);
        }
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&encode_canonical(&invalid_state)?),
            Err(ErasureErrorV1::PolicyConflict)
        );
        Ok(())
    }

    #[test]
    fn receipt_constructor_rejects_retained_wire_boundaries() {
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::Authorized,
                Vec::new(),
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::Complete,
                Vec::new(),
                Vec::new(),
                Vec::new()
            )),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert_eq!(
            ErasureReceiptV1::new(receipt_input(
                ErasureLifecycleV1::PartialFailure,
                vec![acknowledgement(1, ErasureAcknowledgementOutcomeV1::Stale)],
                vec![reference(8)],
                vec![reference(8)]
            )),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }
}
