//! ADR-060's payload-free ERQ1, ERS1, and ERC1 public contracts.
//!
//! This module deliberately excludes storage implementations, key destruction,
//! artifact work, backup inventory, and replay evaluation. Those operations
//! belong to the adapters and follow-up tickets named by ADR-060.

use std::cmp::Ordering;

const VERSION: u64 = 1;
const ERQ1: &str = "ERQ1";
const ERS1: &str = "ERS1";
const ERC1: &str = "ERC1";
const ERCR1: &str = "ERCR1";

/// Largest encoded ERQ1 or ERS1 accepted by V1.
pub const ERASURE_REQUEST_OR_STATE_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded ERC1 accepted by V1.
pub const ERASURE_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest encoded durable ERQ1/ERS1/ERC1 coordinator record accepted by V1.
pub const ERASURE_COORDINATOR_RECORD_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Largest selector or owner collection accepted by V1.
pub const ERASURE_MAX_REFERENCES: usize = 4_096;
/// Largest number of entries in each ERC1 inventory.
pub const ERASURE_MAX_INVENTORY_RESULTS: usize = 65_536;
/// Largest encoded portable supporting record, except retry admissions.
pub const ERASURE_PORTABLE_RECORD_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded retry-admission record.
pub const ERASURE_RETRY_ADMISSION_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Independent ordinal ceiling for attempt outcomes or ERC1 receipts.
///
/// The 64 MiB aggregate ledger bound remains authoritative and may bind
/// before this defensive cardinality ceiling for unusually large evidence.
pub const ERASURE_MAX_ATTEMPT_OUTCOMES: usize = 4_096;
/// Maximum number of administrative resolutions per ERQ1.
pub const ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS: usize = 4_096;

/// Domain tag for correction-provenance records.
pub const ERASURE_CORRECTION_PROVENANCE_TAG_V1: &str = "ERCP1";
/// Domain tag for retry-admission records.
pub const ERASURE_RETRY_ADMISSION_TAG_V1: &str = "ERRA1";
/// Domain tag for acknowledgement-provenance records.
pub const ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1: &str = "ERAP1";
/// Domain tag for attempt-outcome records.
pub const ERASURE_ATTEMPT_OUTCOME_TAG_V1: &str = "ERAO1";
/// Domain tag for receipt-provenance records.
pub const ERASURE_RECEIPT_PROVENANCE_TAG_V1: &str = "ERPR1";
/// Domain tag for administrative-resolution records.
pub const ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1: &str = "ERAR1";
/// Domain tag for immutable scope-commitment records.
pub const ERASURE_SCOPE_COMMITMENT_TAG_V1: &str = "ERSC1";
/// Domain tag for immutable access-freeze provenance records.
pub const ERASURE_FREEZE_PROVENANCE_TAG_V1: &str = "ERFP1";
/// Domain tag for immutable access-freeze failure records.
pub const ERASURE_FREEZE_FAILURE_TAG_V1: &str = "ERFF1";

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
            Self::Authorized => matches!(next, Self::AccessFrozen | Self::Rejected),
            Self::AccessFrozen => matches!(next, Self::DestructionDispatched),
            Self::DestructionDispatched => matches!(next, Self::AwaitingAcknowledgements),
            Self::AwaitingAcknowledgements => matches!(next, Self::Complete | Self::PartialFailure),
            Self::PartialFailure => matches!(next, Self::PartialFailure | Self::Complete),
            Self::Complete | Self::Rejected => false,
        }
    }
    /// Report whether the request itself has reached a terminal outcome.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Rejected)
    }
    /// Report whether the current destruction attempt has reached an outcome.
    #[must_use]
    pub const fn is_attempt_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::PartialFailure | Self::Rejected)
    }
}

/// Closed actions permitted for administrative erasure recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureAdministrativeResolutionActionV1 {
    /// Close a containment boundary after exact evidence validation.
    CloseContainment,
    /// Repair evidence whose canonical bytes already match its address.
    RecoverExactEvidence,
}

impl ErasureAdministrativeResolutionActionV1 {
    /// Return the stable V1 wire code.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::CloseContainment => 0,
            Self::RecoverExactEvidence => 1,
        }
    }

    /// Decode a stable V1 wire code.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::InvalidEncoding`] for an unknown code.
    pub const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::CloseContainment),
            1 => Ok(Self::RecoverExactEvidence),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// Construction fields for an [`ErasureCorrectionProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureCorrectionProvenanceInputV1 {
    /// Rejected ERQ1 digest.
    pub rejected_request: ErasureReferenceV1,
    /// Rejected terminal ERS1 digest.
    pub rejected_terminal_state: ErasureReferenceV1,
    /// Digest of the correction reason.
    pub correction_reason: ErasureReferenceV1,
    /// Host authorization provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed provenance for a corrected rejected request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCorrectionProvenanceV1 {
    input: ErasureCorrectionProvenanceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureCorrectionProvenanceV1 {
    /// Construct and content-address a correction-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if the record exceeds its bound.
    pub fn new(input: ErasureCorrectionProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the rejected ERQ1 digest.
    #[must_use]
    pub const fn rejected_request(&self) -> ErasureReferenceV1 {
        self.input.rejected_request
    }

    /// Return the rejected terminal ERS1 digest.
    #[must_use]
    pub const fn rejected_terminal_state(&self) -> ErasureReferenceV1 {
        self.input.rejected_terminal_state
    }

    /// Return the correction-reason digest.
    #[must_use]
    pub const fn correction_reason(&self) -> ErasureReferenceV1 {
        self.input.correction_reason
    }

    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &correction_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical correction-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(correction_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &correction_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_CORRECTION_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an immutable resolved-scope commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeCommitmentInputV1 {
    /// ERQ1 digest whose selectors were resolved.
    pub request: ErasureReferenceV1,
    /// Canonical affected Timeline/Fork references resolved by the host.
    pub affected_scope: Vec<ErasureReferenceV1>,
    /// Digest of the exact frozen target closure.
    pub target_closure: ErasureReferenceV1,
    /// Optional predecessor extension head.
    pub extension_head: Option<ErasureReferenceV1>,
}

/// Content-addressed resolved scope frozen before destructive work begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeCommitmentV1 {
    input: ErasureScopeCommitmentInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureScopeCommitmentV1 {
    /// Normalize and content-address one resolved scope.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized scope.
    pub fn new(mut input: ErasureScopeCommitmentInputV1) -> Result<Self, ErasureErrorV1> {
        input.affected_scope.sort_unstable();
        if input.affected_scope.is_empty()
            || input.affected_scope.len() > ERASURE_MAX_REFERENCES
            || has_duplicate(&input.affected_scope)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return canonical affected Timeline/Fork references.
    #[must_use]
    pub fn affected_scope(&self) -> &[ErasureReferenceV1] {
        &self.input.affected_scope
    }
    /// Return the frozen target-closure digest.
    #[must_use]
    pub const fn target_closure(&self) -> ErasureReferenceV1 {
        self.input.target_closure
    }
    /// Return the predecessor extension head, when present.
    #[must_use]
    pub const fn extension_head(&self) -> Option<ErasureReferenceV1> {
        self.input.extension_head
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds the portable bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &scope_commitment_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }
    /// Decode one canonical scope commitment.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(scope_commitment_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_commitment_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_SCOPE_COMMITMENT_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for immutable access-freeze provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Scope commitment frozen by this operation.
    pub scope_commitment: ErasureReferenceV1,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Host-authenticated freeze evidence.
    pub evidence: ErasureReferenceV1,
    /// Optional predecessor extension head.
    pub extension_head: Option<ErasureReferenceV1>,
}

/// Content-addressed proof of one successful access freeze.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeProvenanceV1 {
    input: ErasureFreezeProvenanceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureFreezeProvenanceV1 {
    /// Content-address one successful freeze.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn new(input: ErasureFreezeProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the immutable scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }
    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
    }
    /// Return host-authenticated evidence.
    #[must_use]
    pub const fn evidence(&self) -> ErasureReferenceV1 {
        self.input.evidence
    }
    /// Return the predecessor extension head.
    #[must_use]
    pub const fn extension_head(&self) -> Option<ErasureReferenceV1> {
        self.input.extension_head
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }
    /// Decode one canonical freeze provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 7).and_then(freeze_provenance_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for a canonical access-freeze failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeFailureInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Closed failure returned by scope resolution or access freeze.
    pub error: ErasureErrorV1,
    /// Authorization evidence for the failed attempt.
    pub authorization_provenance: ErasureReferenceV1,
    /// Host failure evidence, or the authorization reference when unavailable.
    pub evidence: ErasureReferenceV1,
}

/// Content-addressed failure proving why an authorized request was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeFailureV1 {
    input: ErasureFreezeFailureInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureFreezeFailureV1 {
    /// Construct one closed failure record.
    ///
    /// # Errors
    ///
    /// Returns policy conflict unless the error belongs to scope/freeze admission.
    pub fn new(input: ErasureFreezeFailureInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.error,
            ErasureErrorV1::ScopeInvalid | ErasureErrorV1::AccessFreezeFailed
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }
    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the closed failure.
    #[must_use]
    pub const fn error(&self) -> ErasureErrorV1 {
        self.input.error
    }
    /// Return authorization evidence.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }
    /// Return host failure evidence.
    #[must_use]
    pub const fn evidence(&self) -> ErasureReferenceV1 {
        self.input.evidence
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Encode the deterministic portable record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the portable bound is exceeded.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_failure_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }
    /// Decode one canonical failure record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 6).and_then(freeze_failure_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_failure_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_FAILURE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureRetryAdmissionV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRetryAdmissionInputV1 {
    /// ERQ1 digest being retried.
    pub request: ErasureReferenceV1,
    /// Zero-based attempt ordinal.
    pub attempt_ordinal: u64,
    /// ERC1 digest immediately preceding this attempt, if any.
    pub source_receipt: Option<ErasureReferenceV1>,
    /// Unresolved obligations selected for this attempt.
    pub unresolved_obligations: Vec<ErasureReferenceV1>,
    /// Stable `(ERQ1, target)` command identities corresponding to obligations.
    pub command_identities: Vec<ErasureReferenceV1>,
    /// Pinned retry-policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Authoritative logical position admitting the retry.
    pub admitted_position: u64,
    /// Deterministically derived logical deadline.
    pub deadline_position: u64,
    /// Host authorization-provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed admission for one destruction attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRetryAdmissionV1 {
    input: ErasureRetryAdmissionInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureRetryAdmissionV1 {
    /// Construct, normalize, and content-address a retry admission.
    ///
    /// # Errors
    ///
    /// Returns a closed policy or scope error for an invalid attempt.
    pub fn new(mut input: ErasureRetryAdmissionInputV1) -> Result<Self, ErasureErrorV1> {
        normalize_retry_admission(&mut input)?;
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return the zero-based attempt ordinal.
    #[must_use]
    pub const fn attempt_ordinal(&self) -> u64 {
        self.input.attempt_ordinal
    }

    /// Return the preceding ERC1 digest, if this is a retry.
    #[must_use]
    pub const fn source_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.source_receipt
    }

    /// Return unresolved obligations in bytewise order.
    #[must_use]
    pub fn unresolved_obligations(&self) -> &[ErasureReferenceV1] {
        &self.input.unresolved_obligations
    }

    /// Return stable command identities aligned with [`Self::unresolved_obligations`].
    #[must_use]
    pub fn command_identities(&self) -> &[ErasureReferenceV1] {
        &self.input.command_identities
    }

    /// Return the pinned retry-policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return the logical position that admitted the retry.
    #[must_use]
    pub const fn admitted_position(&self) -> u64 {
        self.input.admitted_position
    }

    /// Return the immutable logical deadline.
    #[must_use]
    pub const fn deadline_position(&self) -> u64 {
        self.input.deadline_position
    }

    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &retry_admission_value(self),
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
        )
    }

    /// Decode one canonical retry-admission record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
            ERASURE_MAX_INVENTORY_RESULTS,
        )
        .and_then(|value| exact_array(&value, 12).and_then(retry_admission_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &retry_admission_value(&self),
            ERASURE_RETRY_ADMISSION_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_RETRY_ADMISSION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAcknowledgementProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAcknowledgementProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Stable `(ERQ1, target)` command identity.
    pub command: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// Immutable obligation identity.
    pub obligation: ErasureReferenceV1,
    /// Immutable owner identity.
    pub owner: ErasureReferenceV1,
    /// Immutable resolved-scope identity.
    pub scope: ErasureReferenceV1,
    /// Closed owner outcome.
    pub outcome: ErasureAcknowledgementOutcomeV1,
    /// Underlying evidence digest.
    pub evidence: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed provenance for one acknowledgement result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAcknowledgementProvenanceV1 {
    input: ErasureAcknowledgementProvenanceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureAcknowledgementProvenanceV1 {
    /// Construct and content-address acknowledgement provenance.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if the record exceeds its bound.
    pub fn new(input: ErasureAcknowledgementProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the stable command identity.
    #[must_use]
    pub const fn command(&self) -> ErasureReferenceV1 {
        self.input.command
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the immutable obligation identity.
    #[must_use]
    pub const fn obligation(&self) -> ErasureReferenceV1 {
        self.input.obligation
    }
    /// Return the immutable owner identity.
    #[must_use]
    pub const fn owner(&self) -> ErasureReferenceV1 {
        self.input.owner
    }
    /// Return the immutable scope identity.
    #[must_use]
    pub const fn scope(&self) -> ErasureReferenceV1 {
        self.input.scope
    }
    /// Return the closed acknowledgement outcome.
    #[must_use]
    pub const fn outcome(&self) -> ErasureAcknowledgementOutcomeV1 {
        self.input.outcome
    }
    /// Return the underlying evidence digest.
    #[must_use]
    pub const fn evidence(&self) -> ErasureReferenceV1 {
        self.input.evidence
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &acknowledgement_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical acknowledgement-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 12).and_then(acknowledgement_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &acknowledgement_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAttemptOutcomeV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAttemptOutcomeInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// ERC1 digest immediately preceding this attempt, if any.
    pub source_receipt: Option<ErasureReferenceV1>,
    /// Attempt outcome lifecycle; only `PartialFailure` or `Complete`.
    pub lifecycle: ErasureLifecycleV1,
    /// Digest of the selected-obligation set.
    pub selected_obligations: ErasureReferenceV1,
    /// Digest of the canonical acknowledgement inventory.
    pub acknowledgement_inventory: ErasureReferenceV1,
    /// Terminal logical position for the attempt.
    pub terminal_position: u64,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed outcome of one destruction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAttemptOutcomeV1 {
    input: ErasureAttemptOutcomeInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureAttemptOutcomeV1 {
    /// Construct and validate one attempt outcome.
    ///
    /// # Errors
    ///
    /// Returns a closed policy error unless the attempt has an outcome.
    pub fn new(input: ErasureAttemptOutcomeInputV1) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            input.lifecycle,
            ErasureLifecycleV1::PartialFailure | ErasureLifecycleV1::Complete
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the preceding ERC1 digest, if any.
    #[must_use]
    pub const fn source_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.source_receipt
    }
    /// Return the attempt outcome lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.input.lifecycle
    }
    /// Return the selected-obligation-set digest.
    #[must_use]
    pub const fn selected_obligations(&self) -> ErasureReferenceV1 {
        self.input.selected_obligations
    }
    /// Return the canonical acknowledgement-inventory digest.
    #[must_use]
    pub const fn acknowledgement_inventory(&self) -> ErasureReferenceV1 {
        self.input.acknowledgement_inventory
    }
    /// Return the terminal logical position.
    #[must_use]
    pub const fn terminal_position(&self) -> u64 {
        self.input.terminal_position
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &attempt_outcome_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical attempt-outcome record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 11).and_then(attempt_outcome_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &attempt_outcome_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ATTEMPT_OUTCOME_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureReceiptProvenanceV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureReceiptProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Attempt identity.
    pub attempt: ErasureReferenceV1,
    /// Zero-based attempt ordinal.
    pub attempt_ordinal: u64,
    /// Immediately preceding ERC1 digest, absent only for ordinal zero.
    pub predecessor_receipt: Option<ErasureReferenceV1>,
    /// Terminal ERS1 digest.
    pub terminal_state: ErasureReferenceV1,
    /// Canonical evidence-set digest.
    pub evidence_set: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Issue logical position.
    pub issue_position: u64,
}

/// Content-addressed provenance for one ERC1 receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureReceiptProvenanceV1 {
    input: ErasureReceiptProvenanceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureReceiptProvenanceV1 {
    /// Construct and validate one receipt-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed policy error for an invalid ordinal or predecessor.
    pub fn new(input: ErasureReceiptProvenanceInputV1) -> Result<Self, ErasureErrorV1> {
        if input.attempt_ordinal >= ERASURE_MAX_ATTEMPT_OUTCOMES as u64
            || (input.attempt_ordinal == 0) != input.predecessor_receipt.is_none()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return the attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> ErasureReferenceV1 {
        self.input.attempt
    }
    /// Return the zero-based attempt ordinal.
    #[must_use]
    pub const fn attempt_ordinal(&self) -> u64 {
        self.input.attempt_ordinal
    }
    /// Return the preceding ERC1 digest, if any.
    #[must_use]
    pub const fn predecessor_receipt(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_receipt
    }
    /// Return the terminal ERS1 digest.
    #[must_use]
    pub const fn terminal_state(&self) -> ErasureReferenceV1 {
        self.input.terminal_state
    }
    /// Return the canonical evidence-set digest.
    #[must_use]
    pub const fn evidence_set(&self) -> ErasureReferenceV1 {
        self.input.evidence_set
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return the issue logical position.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.input.issue_position
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &receipt_provenance_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical receipt-provenance record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 11).and_then(receipt_provenance_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &receipt_provenance_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_RECEIPT_PROVENANCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an [`ErasureAdministrativeResolutionV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAdministrativeResolutionInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Affected state/evidence digests in bytewise order.
    pub affected_digests: Vec<ErasureReferenceV1>,
    /// Closed recovery action.
    pub action: ErasureAdministrativeResolutionActionV1,
    /// Affected scope-commitment digest.
    pub scope_commitment: ErasureReferenceV1,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Authorizing Principal digest.
    pub principal: ErasureReferenceV1,
    /// Host authorization-provenance digest.
    pub authorization_provenance: ErasureReferenceV1,
    /// Digest of the resolution reason.
    pub reason: ErasureReferenceV1,
    /// Issue logical position.
    pub issue_position: u64,
    /// Immediately preceding resolution digest, if any.
    pub predecessor_resolution: Option<ErasureReferenceV1>,
}

/// Content-addressed administrative recovery resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAdministrativeResolutionV1 {
    input: ErasureAdministrativeResolutionInputV1,
    content_digest: ErasureReferenceV1,
}

/// Portable immutable evidence persisted with an erasure coordinator record.
///
/// This envelope is shared by every storage adapter. Empty evidence is valid
/// before the first attempt outcome; once appended, entries are never removed
/// or replaced.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErasureSupportingRecordsV1 {
    correction_provenance: Option<ErasureCorrectionProvenanceV1>,
    scope_commitment: Option<ErasureScopeCommitmentV1>,
    freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    freeze_failure: Option<ErasureFreezeFailureV1>,
    retry_admissions: Vec<ErasureRetryAdmissionV1>,
    acknowledgement_provenance: Vec<ErasureAcknowledgementProvenanceV1>,
    attempt_outcomes: Vec<ErasureAttemptOutcomeV1>,
    receipts: Vec<ErasureReceiptV1>,
    receipt_provenance: Vec<ErasureReceiptProvenanceV1>,
    administrative_resolutions: Vec<ErasureAdministrativeResolutionV1>,
}

/// Construction fields for [`ErasureSupportingRecordsV1`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErasureSupportingRecordsInputV1 {
    /// Provenance linking a corrected ERQ1 to a rejected predecessor.
    pub correction_provenance: Option<ErasureCorrectionProvenanceV1>,
    /// Immutable resolved scope, once freeze resolution succeeds.
    pub scope_commitment: Option<ErasureScopeCommitmentV1>,
    /// Immutable successful freeze evidence.
    pub freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    /// Immutable scope/freeze failure evidence for an authorized rejection.
    pub freeze_failure: Option<ErasureFreezeFailureV1>,
    /// Initial-attempt and retry admissions in ordinal order.
    pub retry_admissions: Vec<ErasureRetryAdmissionV1>,
    /// Canonical acknowledgement-result evidence retained across attempts.
    pub acknowledgement_provenance: Vec<ErasureAcknowledgementProvenanceV1>,
    /// Immutable attempt outcomes in ordinal order.
    pub attempt_outcomes: Vec<ErasureAttemptOutcomeV1>,
    /// Immutable ERC1 receipts in ordinal order.
    pub receipts: Vec<ErasureReceiptV1>,
    /// Provenance for each receipt in ordinal order.
    pub receipt_provenance: Vec<ErasureReceiptProvenanceV1>,
    /// Non-branching administrative-resolution chain.
    pub administrative_resolutions: Vec<ErasureAdministrativeResolutionV1>,
}

impl ErasureSupportingRecordsV1 {
    /// Encode the canonical portable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the ledger exceeds the coordinator bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &supporting_records_value(self),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical portable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or conflicting evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_MAX_INVENTORY_RESULTS,
        )
        .and_then(|value| supporting_records_from_value(&value))
    }

    /// Validate one complete immutable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed policy or provenance error for a fork, gap, mismatched
    /// request, attempt, receipt, or bounded collection.
    pub fn new(mut input: ErasureSupportingRecordsInputV1) -> Result<Self, ErasureErrorV1> {
        input
            .acknowledgement_provenance
            .sort_unstable_by_key(acknowledgement_provenance_ordering_key);
        input.acknowledgement_provenance.dedup();
        Self::from_canonical_input(input)
    }

    pub(super) fn from_canonical_input(
        input: ErasureSupportingRecordsInputV1,
    ) -> Result<Self, ErasureErrorV1> {
        let records = Self {
            correction_provenance: input.correction_provenance,
            scope_commitment: input.scope_commitment,
            freeze_provenance: input.freeze_provenance,
            freeze_failure: input.freeze_failure,
            retry_admissions: input.retry_admissions,
            acknowledgement_provenance: input.acknowledgement_provenance,
            attempt_outcomes: input.attempt_outcomes,
            receipts: input.receipts,
            receipt_provenance: input.receipt_provenance,
            administrative_resolutions: input.administrative_resolutions,
        };
        records.validate()?;
        encode_limited(
            &supporting_records_value(&records),
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )?;
        Ok(records)
    }

    /// Return correction provenance, when this ERQ1 replaces a rejection.
    #[must_use]
    pub const fn correction_provenance(&self) -> Option<&ErasureCorrectionProvenanceV1> {
        self.correction_provenance.as_ref()
    }

    /// Return the immutable resolved scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> Option<&ErasureScopeCommitmentV1> {
        self.scope_commitment.as_ref()
    }

    /// Return immutable successful freeze evidence.
    #[must_use]
    pub const fn freeze_provenance(&self) -> Option<ErasureFreezeProvenanceV1> {
        self.freeze_provenance
    }

    /// Return immutable freeze-failure evidence.
    #[must_use]
    pub const fn freeze_failure(&self) -> Option<ErasureFreezeFailureV1> {
        self.freeze_failure
    }

    /// Return attempt admissions in ordinal order.
    #[must_use]
    pub fn retry_admissions(&self) -> &[ErasureRetryAdmissionV1] {
        &self.retry_admissions
    }

    /// Return acknowledgement-result evidence.
    #[must_use]
    pub fn acknowledgement_provenance(&self) -> &[ErasureAcknowledgementProvenanceV1] {
        &self.acknowledgement_provenance
    }

    /// Return attempt outcomes in ordinal order.
    #[must_use]
    pub fn attempt_outcomes(&self) -> &[ErasureAttemptOutcomeV1] {
        &self.attempt_outcomes
    }

    /// Return immutable ERC1 receipts in ordinal order.
    #[must_use]
    pub fn receipts(&self) -> &[ErasureReceiptV1] {
        &self.receipts
    }

    /// Return receipt provenance in ordinal order.
    #[must_use]
    pub fn receipt_provenance(&self) -> &[ErasureReceiptProvenanceV1] {
        &self.receipt_provenance
    }

    /// Return the administrative-resolution chain.
    #[must_use]
    pub fn administrative_resolutions(&self) -> &[ErasureAdministrativeResolutionV1] {
        &self.administrative_resolutions
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        if self.freeze_provenance.is_some() && self.freeze_failure.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if let Some(freeze) = self.freeze_provenance {
            let Some(scope) = self.scope_commitment.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let committed_scope = freeze.scope_commitment();
            let resolved_scope = scope.reference();
            let freeze_matches_scope = committed_scope == resolved_scope
                && freeze.extension_head() == scope.extension_head();
            if !freeze_matches_scope {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        if self.freeze_failure.is_some() && self.scope_commitment.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        // Attempt-scoped collection lengths are already bounded by admission
        // ordinals and the cardinality checks below. These two collections can
        // grow independently, so enforce their bounds directly.
        if self
            .administrative_resolutions
            .get(ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS)
            .is_some()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self
            .acknowledgement_provenance
            .get(ERASURE_MAX_INVENTORY_RESULTS)
            .is_some()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.attempt_outcomes.len() != self.receipts.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.receipts.len() != self.receipt_provenance.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.retry_admissions.len() < self.attempt_outcomes.len() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.retry_admissions.len() > self.attempt_outcomes.len().saturating_add(1) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.validate_acknowledgements()?;
        self.validate_attempt_chain()?;
        self.validate_resolution_chain()
    }

    fn validate_attempt_chain(&self) -> Result<(), ErasureErrorV1> {
        let mut expected_predecessor = None;
        let mut receipt_digests = self.receipts.iter().map(ErasureReceiptV1::receipt_digest);
        for (ordinal, admission) in self.retry_admissions.iter().enumerate() {
            let ordinal = ordinal as u64;
            if admission.attempt_ordinal() != ordinal
                || admission.source_receipt() != expected_predecessor
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            expected_predecessor = receipt_digests.next();
        }
        for (ordinal, (((outcome, receipt), provenance), admission)) in self
            .attempt_outcomes
            .iter()
            .zip(&self.receipts)
            .zip(&self.receipt_provenance)
            .zip(&self.retry_admissions)
            .enumerate()
        {
            let ordinal = ordinal as u64;
            let outcome_matches = (
                outcome.request(),
                outcome.attempt(),
                outcome.source_receipt(),
                outcome.lifecycle(),
                outcome.policy(),
                outcome.trust(),
            ) == (
                admission.request(),
                admission.reference(),
                admission.source_receipt(),
                receipt.lifecycle(),
                admission.policy(),
                admission.trust(),
            );
            let provenance_matches = (
                provenance.request(),
                provenance.attempt(),
                provenance.attempt_ordinal(),
                provenance.predecessor_receipt(),
                provenance.terminal_state(),
                provenance.policy(),
                provenance.trust(),
            ) == (
                admission.request(),
                admission.reference(),
                ordinal,
                admission.source_receipt(),
                receipt.terminal_state(),
                admission.policy(),
                admission.trust(),
            );
            let acknowledgement_references = self
                .acknowledgement_provenance
                .iter()
                .filter(|acknowledgement| acknowledgement.attempt() == admission.reference())
                .map(ErasureAcknowledgementProvenanceV1::reference)
                .collect::<Vec<_>>();
            let selected_obligations =
                selected_obligations_reference(admission.unresolved_obligations());
            let acknowledgement_inventory =
                acknowledgement_inventory_reference(&acknowledgement_references);
            let evidence_set = erasure_evidence_set_reference(&acknowledgement_references);
            if !outcome_matches
                || !provenance_matches
                || outcome.selected_obligations() != selected_obligations
                || outcome.acknowledgement_inventory() != acknowledgement_inventory
                || outcome.terminal_position() != provenance.issue_position()
                || provenance.evidence_set() != evidence_set
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if receipt.provenance() != provenance.reference() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }

    fn validate_acknowledgements(&self) -> Result<(), ErasureErrorV1> {
        let mut identities = Vec::with_capacity(self.acknowledgement_provenance.len());
        for acknowledgement in &self.acknowledgement_provenance {
            let admission = self
                .retry_admissions
                .iter()
                .find(|admission| admission.reference() == acknowledgement.attempt())
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let command_matches_obligation = admission
                .unresolved_obligations()
                .iter()
                .zip(admission.command_identities())
                .any(|(obligation, command)| {
                    *obligation == acknowledgement.obligation()
                        && *command == acknowledgement.command()
                });
            if admission.request() != acknowledgement.request()
                || !command_matches_obligation
                || admission.policy() != acknowledgement.policy()
                || admission.trust() != acknowledgement.trust()
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            identities.push((
                acknowledgement.command(),
                acknowledgement.attempt(),
                acknowledgement.owner(),
            ));
        }
        if !self.acknowledgement_provenance.windows(2).all(|pair| {
            acknowledgement_provenance_ordering_key(&pair[0])
                < acknowledgement_provenance_ordering_key(&pair[1])
        }) || has_duplicate(&identities)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    fn validate_resolution_chain(&self) -> Result<(), ErasureErrorV1> {
        let mut predecessor = None;
        for resolution in &self.administrative_resolutions {
            if resolution.predecessor_resolution() != predecessor {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            predecessor = Some(resolution.reference());
        }
        Ok(())
    }

    fn validates_request(&self, request: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        let attempts_match = self
            .scope_commitment
            .as_ref()
            .is_none_or(|record| record.request() == request)
            && self
                .freeze_provenance
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_failure
                .is_none_or(|record| record.request() == request)
            && self
                .retry_admissions
                .iter()
                .all(|record| record.request() == request)
            && self
                .acknowledgement_provenance
                .iter()
                .all(|record| record.request() == request)
            && self
                .attempt_outcomes
                .iter()
                .all(|record| record.request() == request)
            && self
                .receipt_provenance
                .iter()
                .all(|record| record.request() == request)
            && self
                .administrative_resolutions
                .iter()
                .all(|record| record.request() == request)
            && self
                .receipts
                .iter()
                .all(|record| record.0.request == request);
        if attempts_match {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }

    fn is_prefix_of(&self, next: &Self) -> bool {
        [
            option_is_unchanged(
                self.correction_provenance.as_ref(),
                next.correction_provenance.as_ref(),
            ),
            option_is_unchanged(
                self.scope_commitment.as_ref(),
                next.scope_commitment.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_provenance.as_ref(),
                next.freeze_provenance.as_ref(),
            ),
            option_is_unchanged(self.freeze_failure.as_ref(), next.freeze_failure.as_ref()),
            next.retry_admissions.starts_with(&self.retry_admissions),
            self.acknowledgement_provenance.iter().all(|record| {
                next.acknowledgement_provenance
                    .binary_search_by_key(
                        &acknowledgement_provenance_ordering_key(record),
                        acknowledgement_provenance_ordering_key,
                    )
                    .is_ok()
            }),
            next.attempt_outcomes.starts_with(&self.attempt_outcomes),
            next.receipts.starts_with(&self.receipts),
            next.receipt_provenance
                .starts_with(&self.receipt_provenance),
            next.administrative_resolutions
                .starts_with(&self.administrative_resolutions),
        ]
        .into_iter()
        .all(std::convert::identity)
    }
}

const fn acknowledgement_provenance_ordering_key(
    acknowledgement: &ErasureAcknowledgementProvenanceV1,
) -> (
    ErasureReferenceV1,
    ErasureReferenceV1,
    ErasureReferenceV1,
    ErasureReferenceV1,
) {
    (
        acknowledgement.command(),
        acknowledgement.attempt(),
        acknowledgement.owner(),
        acknowledgement.reference(),
    )
}

fn option_is_unchanged<T: PartialEq>(current: Option<&T>, next: Option<&T>) -> bool {
    current.is_none_or(|value| next == Some(value))
}

impl ErasureAdministrativeResolutionV1 {
    /// Construct, normalize, and content-address an administrative resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized set.
    pub fn new(mut input: ErasureAdministrativeResolutionInputV1) -> Result<Self, ErasureErrorV1> {
        if input.affected_digests.is_empty()
            || input.affected_digests.len() > ERASURE_MAX_REFERENCES
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        input.affected_digests.sort_unstable();
        if has_duplicate(&input.affected_digests) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }
    /// Return affected state/evidence digests in bytewise order.
    #[must_use]
    pub fn affected_digests(&self) -> &[ErasureReferenceV1] {
        &self.input.affected_digests
    }
    /// Return the closed recovery action.
    #[must_use]
    pub const fn action(&self) -> ErasureAdministrativeResolutionActionV1 {
        self.input.action
    }
    /// Return the affected scope-commitment digest.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }
    /// Return the pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }
    /// Return the pinned trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }
    /// Return the authorizing Principal digest.
    #[must_use]
    pub const fn principal(&self) -> ErasureReferenceV1 {
        self.input.principal
    }
    /// Return the host authorization-provenance digest.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }
    /// Return the resolution-reason digest.
    #[must_use]
    pub const fn reason(&self) -> ErasureReferenceV1 {
        self.input.reason
    }
    /// Return the issue logical position.
    #[must_use]
    pub const fn issue_position(&self) -> u64 {
        self.input.issue_position
    }
    /// Return the preceding resolution digest, if any.
    #[must_use]
    pub const fn predecessor_resolution(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_resolution
    }
    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }
    /// Alias for [`Self::reference`].
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.reference()
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical administrative-resolution record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_REFERENCES,
        )
        .and_then(|value| exact_array(&value, 13).and_then(administrative_resolution_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &administrative_resolution_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

fn normalize_retry_admission(
    input: &mut ErasureRetryAdmissionInputV1,
) -> Result<(), ErasureErrorV1> {
    if !(0..ERASURE_MAX_ATTEMPT_OUTCOMES as u64).contains(&input.attempt_ordinal) {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if (input.attempt_ordinal == 0) != input.source_receipt.is_none() {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input
        .deadline_position
        .checked_sub(input.admitted_position)
        .is_none()
    {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input.unresolved_obligations.is_empty() {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    if input.unresolved_obligations.len() != input.command_identities.len() {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    if input
        .unresolved_obligations
        .get(ERASURE_MAX_INVENTORY_RESULTS)
        .is_some()
    {
        return Err(ErasureErrorV1::ScopeInvalid);
    }

    let mut pairs = input
        .unresolved_obligations
        .iter()
        .copied()
        .zip(input.command_identities.iter().copied())
        .collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(obligation, _)| *obligation);
    let duplicate_obligation = has_duplicate(
        &pairs
            .iter()
            .map(|(obligation, _)| *obligation)
            .collect::<Vec<_>>(),
    );
    let mut commands = input.command_identities.clone();
    commands.sort_unstable();
    if duplicate_obligation || has_duplicate(&commands) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    input.unresolved_obligations = pairs.iter().map(|(obligation, _)| *obligation).collect();
    input.command_identities = pairs.iter().map(|(_, command)| *command).collect();
    Ok(())
}

/// Host-admitted outcome for a submitted ERQ1.
///
/// The decision is part of the authorization-admission key.  A host must
/// durably deduplicate `(request, provenance, decision)` so a retry after a
/// coordinator commit failure cannot re-admit a different lifecycle outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureAuthorizationDecisionV1 {
    /// Permit the request to continue to access freeze.
    Authorized,
    /// Reject the request before access freeze.
    Rejected,
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
    /// Return canonical selectors defining the affected Timeline/Fork scope.
    #[must_use]
    pub fn selectors(&self) -> &[ErasureReferenceV1] {
        &self.0.selectors
    }
    /// Return the pinned request policy.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.0.policy
    }
    /// Return the admitted request position.
    #[must_use]
    pub const fn request_position(&self) -> u64 {
        self.0.request_position
    }
    /// Return the immutable scope horizon.
    #[must_use]
    pub const fn horizon_position(&self) -> u64 {
        self.0.horizon_position
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

/// One deterministic destruction command in the frozen target closure.
///
/// The command identifier is derived from `(request, target)` and therefore
/// remains stable across retries and process restarts.  The command carries
/// no payload; the target closure and the host-owned provenance are the only
/// inputs an adapter may dispatch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErasureDestructionCommandV1 {
    /// The frozen artifact/key/replica target owned by this command.
    pub target: ErasureRequiredTargetV1,
    /// Content-addressed command identity, stable across retries.
    pub command: ErasureReferenceV1,
    /// Host-authenticated dispatch provenance.
    pub provenance: ErasureReferenceV1,
}

impl ErasureDestructionCommandV1 {
    /// Construct the retry-stable command for one frozen target.
    #[must_use]
    pub fn new(
        request: ErasureReferenceV1,
        target: ErasureRequiredTargetV1,
        provenance: ErasureReferenceV1,
    ) -> Self {
        Self {
            target,
            command: destruction_command_reference(request, target),
            provenance,
        }
    }
}

/// Derive the content-addressed identity of one destruction command.
#[must_use]
pub fn destruction_command_reference(
    request: ErasureReferenceV1,
    target: ErasureRequiredTargetV1,
) -> ErasureReferenceV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/erasure-destruction-command/v1");
    hasher.update(&request.digest());
    hasher.update(&target.artifact_class.code().to_be_bytes());
    hasher.update(&target.artifact_digest.digest());
    hasher.update(&target.key_role.code().to_be_bytes());
    hasher.update(&target.key_digest.digest());
    hasher.update(&target.replica_set.digest());
    hasher.update(&target.replica_id.digest());
    ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
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

impl ErasureInventoryResultV1 {
    /// Return the immutable identity of this policy-selected owner obligation.
    #[must_use]
    pub fn obligation_reference(&self) -> ErasureReferenceV1 {
        inventory_obligation_reference(self.category, self.target, self.transition.owner)
    }
}

/// Content-address one applicable category/target/owner obligation.
#[must_use]
pub fn inventory_obligation_reference(
    category: ErasureInventoryCategoryV1,
    target: ErasureRequiredTargetV1,
    owner: ErasureReferenceV1,
) -> ErasureReferenceV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/erasure-obligation/v1");
    hasher.update(&category.code().to_be_bytes());
    hasher.update(&target.artifact_class.code().to_be_bytes());
    hasher.update(&target.artifact_digest.digest());
    hasher.update(&target.key_role.code().to_be_bytes());
    hasher.update(&target.key_digest.digest());
    hasher.update(&target.replica_set.digest());
    hasher.update(&target.replica_id.digest());
    hasher.update(&owner.digest());
    ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
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
    /// Verify that `previous` is the exact monotonic predecessor of this state.
    ///
    /// The check binds the request and coordinator identities, the lifecycle
    /// edge, the access-freeze position, the replay-claim weakening, and the
    /// content-addressed predecessor digest. Storage adapters use this same
    /// rule before accepting a durable state transition.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when the predecessor is
    /// absent, mismatched, or violates the forward-only state contract.
    pub fn validate_predecessor(&self, previous: &Self) -> Result<(), ErasureErrorV1> {
        let Some(previous_digest) = self.previous_state else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let predecessor_is_valid = [
            previous.state_digest() == previous_digest,
            previous.request() == self.request(),
            previous.coordinator() == self.coordinator(),
            previous.lifecycle().permits(self.lifecycle()),
            freeze_is_monotonic(previous.freeze_position(), self.freeze_position()),
            previous
                .replay_claim()
                .preserves_or_weakens(self.replay_claim()),
        ]
        .into_iter()
        .all(|valid| valid);
        if predecessor_is_valid {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
    /// Verify the complete bounded predecessor chain for this state.
    ///
    /// A decoded ERS1 state proves only its own digest and shape. Callers that
    /// load a state from durable storage must also resolve every predecessor
    /// back to the submitted root before treating the state as authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when a predecessor is
    /// absent, malformed, mismatched, or deeper than the V1 history bound.
    pub fn verify_predecessor_chain<R: ErasureStateResolverV1>(
        &self,
        resolver: &R,
    ) -> Result<(), ErasureErrorV1> {
        verify_predecessor_chain(self.clone(), resolver)
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
    /// Immutable policy-selected obligation identity.
    pub obligation: ErasureReferenceV1,
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
        (
            self.obligation,
            self.target,
            self.owner,
            self.evidence,
            self.outcome.code(),
        )
            .cmp(&(
                other.obligation,
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
///
/// Request identity, terminal state, lifecycle, freeze position, target and
/// acknowledgement closures, owner sets, replay claim, and the receipt digest
/// are descriptive at this boundary. The coordinator replaces them with the
/// durable ERS1-derived values before host admission. Caller-owned inventories,
/// policy, trust, provenance, issue position, and signature remain part of the
/// admitted retry identity.
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
            || invalid_owner_sets(&input.pending_owners, &input.failed_owners)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&input.required_targets, &input.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (derived_pending, derived_failed) =
            derived_outcome_owners(&input.inventories, &input.acknowledgements)?;
        if input.pending_owners != derived_pending || input.failed_owners != derived_failed {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !inventories_match_closure(&input.required_targets, &input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // The caller's claim is descriptive input only.  ERC1 records the
        // weakest claim disclosed by the per-artifact transitions.
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        let complete = acknowledgements_match_inventory_obligations(
            &input.inventories,
            &input.acknowledgements,
        ) && input
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
    /// Return the canonical receipt-provenance address.
    #[must_use]
    pub const fn provenance(&self) -> ErasureReferenceV1 {
        self.0.provenance
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
    /// Return the four canonical independently owned evidence inventories.
    #[must_use]
    pub const fn inventories(&self) -> &ErasureReceiptInventoriesV1 {
        &self.0.inventories
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
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> Result<(Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>), ErasureErrorV1> {
    let obligations = inventory_obligations(inventories)?;
    let mut pending = obligations
        .iter()
        .filter(|(obligation, _, _)| {
            !acknowledgements
                .iter()
                .any(|acknowledgement| acknowledgement.obligation == *obligation)
        })
        .map(|(_, _, owner)| *owner)
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
    Ok((pending, failed))
}

fn inventory_obligations(
    inventories: &ErasureReceiptInventoriesV1,
) -> Result<
    Vec<(
        ErasureReferenceV1,
        ErasureRequiredTargetV1,
        ErasureReferenceV1,
    )>,
    ErasureErrorV1,
> {
    let mut obligations = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| {
        (
            entry.obligation_reference(),
            entry.target,
            entry.transition.owner,
        )
    })
    .collect::<Vec<_>>();
    obligations.sort_unstable();
    if obligations.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        Err(ErasureErrorV1::ScopeInvalid)
    } else {
        Ok(obligations)
    }
}

fn acknowledgements_match_inventory_obligations(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    inventory_obligations(inventories).is_ok_and(|obligations| {
        obligations.len() == acknowledgements.len()
            && obligations.iter().all(|(obligation, target, owner)| {
                acknowledgements.iter().any(|acknowledgement| {
                    acknowledgement.obligation == *obligation
                        && acknowledgement.target == *target
                        && acknowledgement.owner == *owner
                })
            })
    })
}

/// Compute the canonical digest for an exact sorted freeze target closure.
///
/// The caller must provide the closure in the canonical order returned by the
/// coordinator after sorting and duplicate rejection.  The digest binds every
/// target coordinate used by ERQ1/ERS1 freeze admission.
#[must_use]
pub fn target_closure_digest(targets: &[ErasureRequiredTargetV1]) -> ErasureReferenceV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/erasure-freeze-closure/v1");
    for target in targets {
        hasher.update(&target.artifact_class.code().to_be_bytes());
        hasher.update(&target.artifact_digest.digest());
        hasher.update(&target.key_role.code().to_be_bytes());
        hasher.update(&target.key_digest.digest());
        hasher.update(&target.replica_set.digest());
        hasher.update(&target.replica_id.digest());
    }
    ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
}

fn reference_set_digest(domain: &[u8], references: &[ErasureReferenceV1]) -> ErasureReferenceV1 {
    let mut references = references.to_vec();
    references.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for reference in references {
        hasher.update(&reference.digest());
    }
    ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
}

/// Content-address a canonical selected-obligation set.
#[must_use]
pub fn selected_obligations_reference(obligations: &[ErasureReferenceV1]) -> ErasureReferenceV1 {
    reference_set_digest(b"pigloros/erasure-selected-obligations/v1", obligations)
}

/// Content-address a canonical acknowledgement-provenance inventory.
#[must_use]
pub fn acknowledgement_inventory_reference(
    acknowledgements: &[ErasureReferenceV1],
) -> ErasureReferenceV1 {
    reference_set_digest(
        b"pigloros/erasure-acknowledgement-inventory/v1",
        acknowledgements,
    )
}

/// Content-address the immutable evidence set bound into receipt provenance.
#[must_use]
pub fn erasure_evidence_set_reference(evidence: &[ErasureReferenceV1]) -> ErasureReferenceV1 {
    reference_set_digest(b"pigloros/erasure-evidence-set/v1", evidence)
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

/// Durable persistence SPI for the complete ERQ1/ERS1/ERC1 coordinator record.
///
/// This port contains only persistence. Authentication, target discovery,
/// destruction dispatch, acknowledgement admission, and receipt trust remain
/// host-owned operations on [`ErasureCoordinatorPortV1`]. It is an adapter
/// seam, not an application command surface: application code must submit
/// erasure operations through [`ErasureCoordinatorStateMachineV1`] so the
/// core validation and lifecycle checks cannot be skipped. Adapters must
/// store canonical bytes and make an exact retry idempotent while rejecting a
/// conflicting replacement.
pub trait ErasurePersistencePortV1: ErasureStateResolverV1 {
    /// Load the authoritative record for one request after a process restart.
    /// Implementations must validate the complete bounded ERS1 predecessor
    /// chain before returning a record; validating only the current row is not
    /// sufficient provenance.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or encoding error when the record cannot be
    /// read or does not satisfy the V1 contract.
    fn load_record(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1>;

    /// Atomically persist the next coordinator record.
    ///
    /// Exact byte-equivalent retries succeed. A different record must be a
    /// valid next state (or a permitted same-state reservation/acknowledgement
    /// extension); otherwise the adapter returns [`ErasureErrorV1::PolicyConflict`].
    ///
    /// # Errors
    ///
    /// Returns a closed storage, encoding, or conflict error.
    fn commit_record(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1>;

    /// Atomically persist an ordered batch of coordinator records.
    ///
    /// The batch is committed as one storage transaction. It is used when a
    /// single coordinator operation needs to record an intermediate recovery
    /// state and its terminal receipt together. Implementations must validate
    /// every record before making any externally visible change.
    ///
    /// # Errors
    ///
    /// Returns a closed storage, encoding, or conflict error and leaves the
    /// durable state unchanged.
    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1>;
}

fn verify_predecessor_chain<R: ErasureStateResolverV1>(
    current: ErasureStateV1,
    resolver: &R,
) -> Result<(), ErasureErrorV1> {
    verify_predecessor_chain_bounded(
        current,
        resolver,
        ERASURE_MAX_ATTEMPT_OUTCOMES.saturating_add(8),
    )
}

fn verify_predecessor_chain_bounded<R: ErasureStateResolverV1>(
    mut current: ErasureStateV1,
    resolver: &R,
    maximum_depth: usize,
) -> Result<(), ErasureErrorV1> {
    for _ in 0..maximum_depth {
        if let Some(previous_digest) = current.previous_state() {
            match resolver.resolve_state(previous_digest) {
                Ok(Some(previous)) => {
                    current.validate_predecessor(&previous)?;
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
    /// Reject a submitted request before access freeze.
    ///
    /// # Errors
    ///
    /// Returns a closed error when host rejection admission or durable commit
    /// fails.
    fn reject(
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
        admission: ErasureRetryAdmissionV1,
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
pub trait ErasureCoordinatorPortV1: ErasurePersistencePortV1 {
    /// Authenticate a request before the state machine records it.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::Unauthorized`] when the host rejects ERQ1.
    fn authenticate(&self, request: &ErasureRequestV1) -> Result<(), ErasureErrorV1>;
    /// Admit one authorization or rejection decision for a submitted request.
    ///
    /// The provenance digest is a reference to host-verified authorization
    /// evidence, not caller-supplied permission. Implementations must verify
    /// the request selectors, policy, and authority before returning success.
    /// Admission is keyed durably by `(request, provenance, decision)` and
    /// must return the same result for an exact retry after commit failure.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::Unauthorized`] or a closed policy error when
    /// the host cannot authenticate the decision.
    fn admit_authorization(
        &self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1>;
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
    /// Resolve the complete affected Timeline/Fork scope at the freeze boundary.
    ///
    /// Ticket #186 owns topology resolution; this #184 port persists its
    /// canonical result without enforcing a store-wide fence.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error when authoritative resolution fails.
    fn affected_scope(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1>;
    /// Authenticate and perform the freeze-boundary operation for `targets`.
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
    /// `request` and the exact `targets` value. The returned closure digest,
    /// Tick Boundary position, and provenance are the host-authenticated
    /// evidence for that reservation.
    /// If the following `commit_record` fails, an exact retry must return the
    /// same admission rather than observe a later Tick Boundary or rediscover
    /// a different closure. This reservation is operational metadata; it does
    /// not replace the committed ERS1 record.
    fn admit_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
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
        commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1>;
    /// Authenticate one initial or retry attempt before its outbox intent is committed.
    ///
    /// # Errors
    ///
    /// Returns a closed policy/trust error when the admission is stale or unauthorized.
    fn admit_attempt(&self, admission: &ErasureRetryAdmissionV1) -> Result<(), ErasureErrorV1>;
    /// Admit an acknowledgement from the authenticated owner and evidence boundary.
    ///
    /// The structural owner/target equality check in the core is necessary but
    /// not sufficient: digests are not identities or signatures. The host
    /// must authenticate the sender and validate the evidence before this
    /// operation returns success. Admission is keyed durably by the complete
    /// `(request, target, owner, evidence, outcome)` identity, so a retry
    /// after coordinator commit failure does not repeat owner-side work.
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
    /// These fields are commitments, not self-authenticating proof. The host
    /// must verify them against its `TrustPolicyRegistry` and signature
    /// admission boundary before returning success. Admission is keyed
    /// durably by the canonical normalized ERC1 input, so a retry after
    /// coordinator commit failure is idempotent across process restarts.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::TrustSnapshotInvalid`] or a closed signature
    /// admission error when the evidence is not trusted.
    fn admit_receipt(&self, input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1>;
}

/// Host-authenticated evidence for the access-freeze boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionV1 {
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Host-authenticated provenance for the freeze transition.
    pub provenance: ErasureReferenceV1,
    /// Digest of the exact sorted target closure reserved by the host. The
    /// state machine compares this with its own canonical closure digest.
    pub target_closure: ErasureReferenceV1,
}

/// Public durable fields for reconstructing an ERQ1/ERS1/ERC1 coordinator record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCoordinatorRecordPartsV1 {
    /// The exact authenticated request identity.
    pub request: ErasureRequestV1,
    /// The latest digest-linked ERS1 state.
    pub state: ErasureStateV1,
    /// Durable target reservation persisted before host freeze admission.
    ///
    /// An Authorized record may carry this reservation while a host admission
    /// or its final coordinator commit is being retried.  It prevents a
    /// restart from rediscovering a different inventory closure.
    pub reserved_targets: Vec<ErasureRequiredTargetV1>,
    /// The frozen required-target closure. Each `(request, target)` tuple is
    /// the deterministic identity of one destruction command; no payload is
    /// persisted in the coordinator record.
    pub targets: Vec<ErasureRequiredTargetV1>,
    /// Acknowledgements accepted for the frozen closure and therefore the
    /// durable command results.
    pub acknowledgements: Vec<ErasureAcknowledgementV1>,
    /// The committed terminal receipt, if any.
    pub receipt: Option<ErasureReceiptV1>,
    /// Canonical normalized terminal input used for idempotent retries.
    pub receipt_input: Option<ErasureReceiptInputV1>,
    /// Authenticated authorization provenance, if present.
    pub authorize_provenance: Option<ErasureReferenceV1>,
    /// Host-authenticated freeze provenance, if present.
    pub freeze_provenance: Option<ErasureReferenceV1>,
    /// Host-authenticated freeze admission evidence, if present.
    pub freeze_admission: Option<ErasureFreezeAdmissionV1>,
    /// Host-authenticated dispatch provenance, if present.
    pub dispatch_provenance: Option<ErasureReferenceV1>,
    /// Immutable retry, acknowledgement, receipt, and recovery evidence.
    pub supporting_records: ErasureSupportingRecordsV1,
}

/// Durable ERQ1/ERS1/ERC1 coordinator record.
///
/// Hosts persist this complete record (or an equivalent representation) and
/// return it from [`ErasurePersistencePortV1::load_record`]. The core state
/// machine keeps only a query cache; it never treats that cache as authority.
/// The `ERCR1` encoding is an internal sidecar envelope for this SPI; ERQ1,
/// ERS1, and ERC1 remain the public contracts described by ADR-060.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCoordinatorRecordV1 {
    /// The exact authenticated request identity.
    request: ErasureRequestV1,
    /// The latest digest-linked ERS1 state.
    state: ErasureStateV1,
    reserved_targets: Vec<ErasureRequiredTargetV1>,
    /// The frozen required-target closure. Each `(request, target)` tuple is
    /// the deterministic identity of one destruction command.
    targets: Vec<ErasureRequiredTargetV1>,
    /// Acknowledgements accepted for the frozen closure and therefore the
    /// durable command results.
    acknowledgements: Vec<ErasureAcknowledgementV1>,
    /// The committed terminal receipt, if any.
    receipt: Option<ErasureReceiptV1>,
    /// Canonical normalized terminal input used for idempotent retries.
    receipt_input: Option<ErasureReceiptInputV1>,
    authorize_provenance: Option<ErasureReferenceV1>,
    freeze_provenance: Option<ErasureReferenceV1>,
    freeze_admission: Option<ErasureFreezeAdmissionV1>,
    dispatch_provenance: Option<ErasureReferenceV1>,
    supporting_records: ErasureSupportingRecordsV1,
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
            reserved_targets: parts.reserved_targets,
            targets: parts.targets,
            acknowledgements: parts.acknowledgements,
            receipt: parts.receipt,
            receipt_input: parts.receipt_input,
            authorize_provenance: parts.authorize_provenance,
            freeze_provenance: parts.freeze_provenance,
            freeze_admission: parts.freeze_admission,
            dispatch_provenance: parts.dispatch_provenance,
            supporting_records: parts.supporting_records,
        };
        record.validate(coordinator).map(|()| record)
    }

    /// Encode the complete durable coordinator record as canonical CBOR.
    ///
    /// The record embeds the canonical ERQ1, ERS1, and (when terminal) ERC1
    /// values. The terminal receipt is also the normalized receipt input, so
    /// it is stored once and reconstructed on load.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the record is invalid or exceeds the V1
    /// durable-record bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate(self.state.coordinator()).and_then(|()| {
            encode_limited(&record_value(self), ERASURE_COORDINATOR_RECORD_MAX_BYTES)
        })
    }

    /// Decode and validate one complete durable coordinator record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, oversized, or
    /// internally inconsistent persisted bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_MAX_INVENTORY_RESULTS,
        )
        .and_then(|value| exact_array(&value, 13).and_then(record_from_fields))
    }

    /// Validate a replacement against the currently persisted record.
    ///
    /// Same-byte retries are idempotent. The only same-state extensions are
    /// the reserved target closure while `Authorized` and additional
    /// acknowledgements while `AwaitingAcknowledgements`; all other changes
    /// require the new ERS1 predecessor link to name this record's state.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::PolicyConflict`] when the replacement is not
    /// a permitted monotonic update.
    pub fn validate_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        let coordinator = self.state.coordinator();
        self.validate(coordinator)?;
        next.validate(coordinator)?;
        if self.request != next.request {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self
            .supporting_records
            .is_prefix_of(&next.supporting_records)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !freeze_is_monotonic(self.state.freeze_position(), next.state.freeze_position()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self
            .state
            .replay_claim()
            .preserves_or_weakens(next.state.replay_claim())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self == next {
            return Ok(());
        }
        if self.state.state_digest() == next.state.state_digest() {
            return self.validate_same_state_replacement(next);
        }
        self.validate_advanced_replacement(next)
    }

    fn validate_same_state_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        let mut without_supporting_records = next.clone();
        without_supporting_records
            .supporting_records
            .clone_from(&self.supporting_records);
        if without_supporting_records == *self {
            return Ok(());
        }
        if matches!(
            (
                self.state.lifecycle(),
                self.reserved_targets.is_empty(),
                next.reserved_targets.is_empty(),
            ),
            (ErasureLifecycleV1::Authorized, true, false)
        ) {
            let mut without_reservation = next.clone();
            without_reservation.reserved_targets.clear();
            without_reservation
                .supporting_records
                .clone_from(&self.supporting_records);
            if without_reservation == *self {
                return Ok(());
            }
        }
        if matches!(
            (
                self.state.lifecycle(),
                self.dispatch_provenance,
                next.dispatch_provenance,
            ),
            (ErasureLifecycleV1::AccessFrozen, None, Some(_))
        ) {
            let mut without_dispatch_intent = next.clone();
            without_dispatch_intent.dispatch_provenance = None;
            without_dispatch_intent
                .supporting_records
                .clone_from(&self.supporting_records);
            if without_dispatch_intent == *self {
                return Ok(());
            }
        }
        if matches!(
            (
                self.state.lifecycle(),
                self.acknowledgements
                    .iter()
                    .all(|acknowledgement| next.acknowledgements.contains(acknowledgement)),
                next.acknowledgements != self.acknowledgements,
            ),
            (
                ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure,
                true,
                true,
            )
        ) {
            let mut without_new_acknowledgements = next.clone();
            without_new_acknowledgements
                .acknowledgements
                .clone_from(&self.acknowledgements);
            without_new_acknowledgements
                .supporting_records
                .clone_from(&self.supporting_records);
            if without_new_acknowledgements == *self {
                return Ok(());
            }
        }
        if self.state.lifecycle() == ErasureLifecycleV1::PartialFailure
            && next.acknowledgements.is_empty()
            && self
                .supporting_records
                .retry_admissions
                .len()
                .saturating_add(1)
                == next.supporting_records.retry_admissions.len()
        {
            let mut without_retry = next.clone();
            without_retry
                .acknowledgements
                .clone_from(&self.acknowledgements);
            without_retry
                .supporting_records
                .clone_from(&self.supporting_records);
            if without_retry == *self {
                return Ok(());
            }
        }
        Err(ErasureErrorV1::PolicyConflict)
    }

    fn validate_advanced_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        if next.state.previous_state() != Some(self.state.state_digest()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self.state.lifecycle().permits(next.state.lifecycle()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let targets_continue = if next.targets == self.targets {
            true
        } else if self.state.lifecycle() == ErasureLifecycleV1::Authorized {
            // `permits` above restricts Authorized to AccessFrozen, so the
            // reserved closure is the only legal target change on this edge.
            next.targets == self.reserved_targets
        } else {
            false
        };
        if !targets_continue {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self
            .acknowledgements
            .iter()
            .all(|acknowledgement| next.acknowledgements.contains(acknowledgement))
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.authorize_provenance.is_some()
            && self.authorize_provenance != next.authorize_provenance
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.freeze_provenance.is_some() && self.freeze_provenance != next.freeze_provenance {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.dispatch_provenance.is_some()
            && self.dispatch_provenance != next.dispatch_provenance
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
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

    /// Return the durable target reservation awaiting freeze admission.
    #[must_use]
    pub fn reserved_targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.reserved_targets
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

    /// Return host-authenticated freeze admission evidence, if present.
    #[must_use]
    pub const fn freeze_admission(&self) -> Option<ErasureFreezeAdmissionV1> {
        self.freeze_admission
    }

    /// Return the host-authenticated dispatch provenance, if present.
    #[must_use]
    pub const fn dispatch_provenance(&self) -> Option<ErasureReferenceV1> {
        self.dispatch_provenance
    }

    /// Return immutable supporting records recovered with this coordinator state.
    #[must_use]
    pub const fn supporting_records(&self) -> &ErasureSupportingRecordsV1 {
        &self.supporting_records
    }

    /// Validate the rejected predecessor named by correction provenance.
    ///
    /// # Errors
    ///
    /// Returns provenance missing unless the predecessor is the exact rejected
    /// ERQ1/terminal ERS1 pair named by this record.
    pub fn validate_correction_predecessor(
        &self,
        predecessor: &Self,
    ) -> Result<(), ErasureErrorV1> {
        let correction = self
            .supporting_records
            .correction_provenance()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if predecessor.request.reference() == correction.rejected_request()
            && predecessor.state.lifecycle() == ErasureLifecycleV1::Rejected
            && predecessor.state.state_digest() == correction.rejected_terminal_state()
        {
            Ok(())
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }

    fn validate_scope(&self) -> Result<(), ErasureErrorV1> {
        if self.reserved_targets.len() > ERASURE_MAX_INVENTORY_RESULTS {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if self.targets.len() > ERASURE_MAX_INVENTORY_RESULTS {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // Acknowledgements are unique members of the bounded target closure;
        // the closure-subset check below therefore bounds their count too.
        if !self
            .reserved_targets
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !self.targets.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if has_duplicate_by_target(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !strictly_increasing(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&self.targets, &self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(())
    }

    fn validate_lifecycle_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Rejected
        ) && (!self.reserved_targets.is_empty()
            || !self.targets.is_empty()
            || !self.acknowledgements.is_empty()
            || self.receipt.is_some()
            || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::Authorized
            && (!self.targets.is_empty()
                || !self.acknowledgements.is_empty()
                || self.receipt.is_some()
                || self.receipt_input.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle != ErasureLifecycleV1::Authorized && !self.reserved_targets.is_empty() {
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
        Ok(())
    }

    fn validate_freeze_admission(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        if matches!(
            lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        ) {
            let Some(admission) = self.freeze_admission else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(scope) = self.supporting_records.scope_commitment() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(freeze) = self.supporting_records.freeze_provenance() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            if admission.target_closure != target_closure_digest(&self.targets)
                || scope.target_closure() != admission.target_closure
                || freeze.scope_commitment() != scope.reference()
                || freeze.evidence() != admission.provenance
                || Some(freeze.reference()) != self.freeze_provenance
                || Some(admission.freeze_position) != self.state.freeze_position()
                || freeze.freeze_position() != admission.freeze_position
                || (lifecycle == ErasureLifecycleV1::AccessFrozen
                    && self.state.provenance() != freeze.reference())
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::Rejected
        ) && self.freeze_admission.is_some()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    fn validate_provenance(&self, lifecycle: ErasureLifecycleV1) -> Result<(), ErasureErrorV1> {
        // Validate the exact provenance shape, not only its cardinality. A
        // malformed record must not substitute dispatch evidence for the
        // authorization or freeze evidence which precedes it.
        let expected = match lifecycle {
            ErasureLifecycleV1::Submitted => (false, false, false),
            ErasureLifecycleV1::Rejected => (
                self.supporting_records.freeze_failure().is_some(),
                false,
                false,
            ),
            ErasureLifecycleV1::Authorized => (true, false, false),
            // An AccessFrozen record may carry a durable dispatch intent while
            // the host operation is being retried. It is not yet a lifecycle
            // transition, but its identity must survive restart.
            ErasureLifecycleV1::AccessFrozen => (true, true, self.dispatch_provenance.is_some()),
            ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => (true, true, true),
        };
        let actual = (
            self.authorize_provenance.is_some(),
            self.freeze_provenance.is_some(),
            self.dispatch_provenance.is_some(),
        );
        if actual != expected {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn validate_terminal(
        &self,
        lifecycle: ErasureLifecycleV1,
        coordinator: ErasureReferenceV1,
    ) -> Result<(), ErasureErrorV1> {
        if !matches!(
            lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            return Ok(());
        }
        let Some(receipt) = self.receipt.as_ref() else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let Some(receipt_input) = self.receipt_input.as_ref() else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let reconstructed = ErasureReceiptV1::new(receipt_input.clone())?;
        if self.receipt.as_ref() != Some(&reconstructed) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let mut acknowledgements = self.acknowledgements.clone();
        acknowledgements.sort_unstable();
        if receipt.terminal_state().ne(&self.state.state_digest()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.lifecycle().ne(&lifecycle) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.coordinator().ne(&coordinator) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.replay_claim() != self.state.replay_claim() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.0.request.ne(&self.request.reference()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.required_targets().ne(self.targets.as_slice()) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if receipt.acknowledgements().ne(acknowledgements.as_slice()) {
            let active_retry = self.supporting_records.retry_admissions.len()
                == self
                    .supporting_records
                    .attempt_outcomes
                    .len()
                    .saturating_add(1);
            if !active_retry {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        let (pending, failed) =
            derived_outcome_owners(receipt.inventories(), receipt.acknowledgements())?;
        if self.state.pending_owners() != pending.as_slice()
            || self.state.failed_owners() != failed.as_slice()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let outcome = self
            .supporting_records
            .attempt_outcomes()
            .last()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let provenance = self
            .supporting_records
            .receipt_provenance()
            .last()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if self.state.provenance() != outcome.reference()
            || receipt.provenance() != provenance.reference()
            || provenance.terminal_state() != self.state.state_digest()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn validate(&self, coordinator: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        if self.request.reference() != self.state.request()
            || self.state.coordinator() != coordinator
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.supporting_records
            .validates_request(self.request.reference())?;
        if let Some(correction) = self.supporting_records.correction_provenance() {
            if self.request.provenance() != correction.reference() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        let lifecycle = self.state.lifecycle();
        self.validate_supporting_lifecycle(lifecycle)?;
        self.validate_scope()?;
        self.validate_lifecycle_shape(lifecycle)?;
        if !self
            .acknowledgements
            .iter()
            .all(|acknowledgement| self.acknowledgement_has_provenance(acknowledgement))
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.validate_freeze_admission(lifecycle)?;
        self.validate_provenance(lifecycle)?;
        self.validate_terminal(lifecycle, coordinator)?;
        Ok(())
    }

    fn acknowledgement_has_provenance(&self, acknowledgement: &ErasureAcknowledgementV1) -> bool {
        let command =
            destruction_command_reference(self.request.reference(), acknowledgement.target);
        let Some(scope) = self.supporting_records.scope_commitment() else {
            return false;
        };
        self.supporting_records
            .acknowledgement_provenance()
            .iter()
            .filter(|provenance| {
                provenance.request() == self.request.reference()
                    && provenance.command() == command
                    && provenance.obligation() == acknowledgement.obligation
                    && provenance.owner() == acknowledgement.owner
                    && provenance.scope() == scope.reference()
                    && provenance.outcome() == acknowledgement.outcome
                    && provenance.evidence() == acknowledgement.evidence
            })
            .any(|provenance| {
                self.admission_supports_acknowledgement(provenance, acknowledgement, command)
            })
    }

    fn admission_supports_acknowledgement(
        &self,
        provenance: &ErasureAcknowledgementProvenanceV1,
        acknowledgement: &ErasureAcknowledgementV1,
        command: ErasureReferenceV1,
    ) -> bool {
        self.supporting_records
            .retry_admissions()
            .iter()
            .filter(|admission| admission.reference() == provenance.attempt())
            .filter(|admission| admission.policy() == provenance.policy())
            .filter(|admission| admission.trust() == provenance.trust())
            .any(|admission| {
                admission
                    .unresolved_obligations()
                    .iter()
                    .zip(admission.command_identities())
                    .any(|(obligation, admitted_command)| {
                        *obligation == acknowledgement.obligation && *admitted_command == command
                    })
            })
    }

    fn validate_supporting_lifecycle(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        let scope = self.supporting_records.scope_commitment();
        let freeze = self.supporting_records.freeze_provenance();
        let failure = self.supporting_records.freeze_failure();
        match lifecycle {
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Authorized => {
                if scope.is_some() || freeze.is_some() || failure.is_some() {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
            }
            ErasureLifecycleV1::Rejected => {
                if let Some(failure) = failure {
                    if scope.is_some()
                        || freeze.is_some()
                        || failure.authorization_provenance()
                            != self
                                .authorize_provenance
                                .ok_or(ErasureErrorV1::ProvenanceMissing)?
                        || self.state.provenance() != failure.reference()
                    {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                }
            }
            ErasureLifecycleV1::AccessFrozen
            | ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => {
                if scope.is_none() || freeze.is_none() || failure.is_some() {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
        }
        let has_attempt_evidence = !self.supporting_records.retry_admissions().is_empty()
            || !self
                .supporting_records
                .acknowledgement_provenance()
                .is_empty()
            || !self.supporting_records.attempt_outcomes().is_empty()
            || !self.supporting_records.receipts().is_empty()
            || !self.supporting_records.receipt_provenance().is_empty();
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Submitted
                | ErasureLifecycleV1::Authorized
                | ErasureLifecycleV1::Rejected
        ) && has_attempt_evidence
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::AccessFrozen {
            let admissions = self.supporting_records.retry_admissions();
            let dispatch_intent_matches = match (self.dispatch_provenance, admissions) {
                (None, []) => true,
                (Some(provenance), [admission]) => provenance == admission.reference(),
                _ => false,
            };
            if !dispatch_intent_matches
                || !self
                    .supporting_records
                    .acknowledgement_provenance()
                    .is_empty()
                || !self.supporting_records.attempt_outcomes().is_empty()
                || !self.supporting_records.receipts().is_empty()
                || !self.supporting_records.receipt_provenance().is_empty()
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
        ) {
            let admission = self
                .supporting_records
                .retry_admissions()
                .last()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            if self.state.provenance() != admission.reference()
                || self.dispatch_provenance != Some(admission.reference())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
        ) {
            let latest_receipt = self.supporting_records.receipts().last();
            if latest_receipt != self.receipt.as_ref() {
                return Err(ErasureErrorV1::ProvenanceMissing);
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
            Ok(Some(record)) => record
                .validate(self.coordinator)
                .and_then(|()| verify_predecessor_chain(record.state.clone(), &self.port))
                .map(|()| {
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
    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        records
            .iter()
            .try_for_each(|record| record.validate(self.coordinator))?;
        self.port.commit_records(records)?;
        records
            .iter()
            .cloned()
            .for_each(|record| self.cache(record));
        Ok(())
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
            Ok(Some(record)) => record
                .validate(self.coordinator)
                .and_then(|()| verify_predecessor_chain(record.state.clone(), &self.port))
                .and_then(|()| {
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
                            reserved_targets: Vec::new(),
                            targets: Vec::new(),
                            acknowledgements: Vec::new(),
                            receipt: None,
                            receipt_input: None,
                            authorize_provenance: None,
                            freeze_provenance: None,
                            freeze_admission: None,
                            dispatch_provenance: None,
                            supporting_records: ErasureSupportingRecordsV1::default(),
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
                        || record.state.lifecycle().is_attempt_terminal()
                        || record.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
                        || record.state.lifecycle() == ErasureLifecycleV1::DestructionDispatched
                        || record.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements)
                {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            self.port.admit_authorization(
                request,
                provenance,
                ErasureAuthorizationDecisionV1::Authorized,
            )?;
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
    /// Reject a submitted ERQ1 after host policy admission; an exact retry is
    /// a query of the already committed terminal state.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown request, failed host admission,
    /// or a non-monotonic state transition.
    pub fn reject(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() != ErasureLifecycleV1::Submitted {
                return if record.state.lifecycle() == ErasureLifecycleV1::Rejected
                    && record.state.provenance() == provenance
                {
                    Ok(record.state)
                } else {
                    Err(ErasureErrorV1::PolicyConflict)
                };
            }
            self.port.admit_authorization(
                request,
                provenance,
                ErasureAuthorizationDecisionV1::Rejected,
            )?;
            let replay_claim = record.state.replay_claim();
            record
                .state
                .transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::Rejected,
                    freeze_position: None,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim,
                    provenance,
                })
                .and_then(|state| {
                    record.state = state;
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
            if let Some(failure) = record.supporting_records.freeze_failure() {
                return Err(failure.error());
            }
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
            let targets =
                self.reserve_freeze_targets(request, &mut record, requested_transition.provenance)?;
            let (scope_commitment, admission) =
                self.admit_freeze_evidence(request, &mut record, &requested_transition, &targets)?;
            let freeze_provenance =
                ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
                    request,
                    scope_commitment: scope_commitment.reference(),
                    freeze_position: admission.freeze_position,
                    evidence: admission.provenance,
                    extension_head: scope_commitment.extension_head(),
                })?;
            let provenance = freeze_provenance.reference();
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
                .and_then(|state| {
                    record.state = state;
                    record.freeze_provenance = Some(provenance);
                    record.freeze_admission = Some(admission);
                    record.supporting_records.scope_commitment = Some(scope_commitment);
                    record.supporting_records.freeze_provenance = Some(freeze_provenance);
                    record.targets.clone_from(&record.reserved_targets);
                    record.reserved_targets.clear();
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }

    fn admit_freeze_evidence(
        &mut self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        requested: &ErasureStateTransitionV1,
        targets: &[ErasureRequiredTargetV1],
    ) -> Result<(ErasureScopeCommitmentV1, ErasureFreezeAdmissionV1), ErasureErrorV1> {
        let target_closure = target_closure_digest(targets);
        let affected_scope = match self.port.affected_scope(request) {
            Ok(scope) => scope,
            Err(ErasureErrorV1::ScopeInvalid) => {
                return self.reject_freeze_failure(
                    record,
                    ErasureErrorV1::ScopeInvalid,
                    requested.provenance,
                );
            }
            Err(error) => return Err(error),
        };
        let scope = ErasureScopeCommitmentV1::new(ErasureScopeCommitmentInputV1 {
            request,
            affected_scope,
            target_closure,
            extension_head: None,
        })?;
        let admission = match self.port.admit_freeze(request, requested, targets) {
            Ok(admission) => admission,
            Err(error @ (ErasureErrorV1::ScopeInvalid | ErasureErrorV1::AccessFreezeFailed)) => {
                return self.reject_freeze_failure(record, error, requested.provenance);
            }
            Err(error) => return Err(error),
        };
        if admission.target_closure != target_closure {
            return self.reject_freeze_failure(
                record,
                ErasureErrorV1::ScopeInvalid,
                admission.provenance,
            );
        }
        Ok((scope, admission))
    }

    fn reserve_freeze_targets(
        &mut self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        evidence: ErasureReferenceV1,
    ) -> Result<Vec<ErasureRequiredTargetV1>, ErasureErrorV1> {
        if record.reserved_targets.is_empty() {
            let mut targets = match self.port.required_targets(request) {
                Ok(targets) => targets,
                Err(ErasureErrorV1::ScopeInvalid) => {
                    return self.reject_freeze_failure(
                        record,
                        ErasureErrorV1::ScopeInvalid,
                        evidence,
                    );
                }
                Err(error) => return Err(error),
            };
            if targets.is_empty() || targets.len() > ERASURE_MAX_INVENTORY_RESULTS {
                return self.reject_freeze_failure(record, ErasureErrorV1::ScopeInvalid, evidence);
            }
            targets.sort_unstable();
            if has_duplicate(&targets) {
                return self.reject_freeze_failure(record, ErasureErrorV1::ScopeInvalid, evidence);
            }
            record.reserved_targets = targets;
            self.commit(record.clone())?;
        }
        Ok(record.reserved_targets.clone())
    }

    fn reject_freeze_failure<T>(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        error: ErasureErrorV1,
        evidence: ErasureReferenceV1,
    ) -> Result<T, ErasureErrorV1> {
        let authorization_provenance = record
            .authorize_provenance
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let failure = ErasureFreezeFailureV1::new(ErasureFreezeFailureInputV1 {
            request: record.request.reference(),
            error,
            authorization_provenance,
            evidence,
        })?;
        let replay_claim = record.state.replay_claim();
        record.state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Rejected,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim,
            provenance: failure.reference(),
        })?;
        record.reserved_targets.clear();
        record.supporting_records.freeze_failure = Some(failure);
        self.commit(record.clone())?;
        Err(error)
    }
    /// Dispatch the frozen closure through the host-owned idempotent port.
    ///
    /// A caller cannot claim this lifecycle edge by supplying an ERS1
    /// transition. The dispatch intent is committed before the host call, so
    /// a restart can retry the same target closure without losing its command
    /// identity.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the request is unknown, the lifecycle is
    /// invalid, host dispatch is rejected, or the durable commit fails.
    pub fn dispatch_attempt(
        &mut self,
        request: ErasureReferenceV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() == ErasureLifecycleV1::AwaitingAcknowledgements
                && record.supporting_records.retry_admissions.last() == Some(admission)
            {
                return Ok(record.state);
            }
            let ordinal_index = record.supporting_records.attempt_outcomes.len();
            let ordinal =
                u64::try_from(ordinal_index).map_err(|_| ErasureErrorV1::PolicyConflict)?;
            let source_receipt = record
                .supporting_records
                .receipts
                .last()
                .map(ErasureReceiptV1::receipt_digest);
            if admission.request() != request
                || admission.attempt_ordinal() != ordinal
                || admission.source_receipt() != source_receipt
                || !matches!(
                    record.state.lifecycle(),
                    ErasureLifecycleV1::AccessFrozen | ErasureLifecycleV1::PartialFailure
                )
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let commands = record
                .targets
                .iter()
                .copied()
                .filter(|target| {
                    admission
                        .command_identities()
                        .contains(&destruction_command_reference(request, *target))
                })
                .map(|target| {
                    ErasureDestructionCommandV1::new(request, target, admission.reference())
                })
                .collect::<Vec<_>>();
            if admission.command_identities().iter().any(|command| {
                !commands
                    .iter()
                    .any(|candidate| candidate.command == *command)
            }) {
                return Err(ErasureErrorV1::ScopeInvalid);
            }
            let already_admitted = record
                .supporting_records
                .retry_admissions
                .get(ordinal_index)
                == Some(admission);
            if !already_admitted {
                self.port.admit_attempt(admission)?;
                record
                    .supporting_records
                    .retry_admissions
                    .push(admission.clone());
                if ordinal == 0 {
                    record.dispatch_provenance = Some(admission.reference());
                } else {
                    record.acknowledgements.clear();
                }
                self.commit(record.clone())?;
            }
            self.port.dispatch_destruction(request, &commands)?;
            if ordinal == 0 {
                let freeze_position = record.state.freeze_position();
                let replay_claim = record.state.replay_claim();
                let dispatched = record.state.transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::DestructionDispatched,
                    freeze_position,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim,
                    provenance: admission.reference(),
                })?;
                record.state = dispatched;
                let dispatched_record = record.clone();
                record.state = record.state.transition(ErasureStateTransitionV1 {
                    lifecycle: ErasureLifecycleV1::AwaitingAcknowledgements,
                    freeze_position,
                    pending_owners: Vec::new(),
                    failed_owners: Vec::new(),
                    acknowledged_targets: Vec::new(),
                    replay_claim,
                    provenance: admission.reference(),
                })?;
                self.commit_records(&[dispatched_record, record.clone()])?;
            }
            Ok(record.state)
        })
    }
    /// Dispatch the initial attempt using request-pinned policy and host provenance.
    ///
    /// Retry callers use [`Self::dispatch_attempt`] with an explicit admission.
    ///
    /// # Errors
    ///
    /// Returns a closed scope, policy, trust, dispatch, or persistence error.
    pub fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let record = self.record(request)?;
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AccessFrozen | ErasureLifecycleV1::AwaitingAcknowledgements
        ) || record.targets.is_empty()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let obligations = record
            .targets
            .iter()
            .copied()
            .map(|target| {
                inventory_obligation_reference(
                    ErasureInventoryCategoryV1::Artifact,
                    target,
                    target.replica_id,
                )
            })
            .collect::<Vec<_>>();
        let commands = record
            .targets
            .iter()
            .copied()
            .map(|target| destruction_command_reference(request, target))
            .collect::<Vec<_>>();
        let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request,
            attempt_ordinal: 0,
            source_receipt: None,
            unresolved_obligations: obligations,
            command_identities: commands,
            policy: record.request.policy(),
            trust: provenance,
            admitted_position: record.request.request_position(),
            deadline_position: u64::MAX,
            authorization_provenance: provenance,
        })?;
        self.dispatch_attempt(request, &admission)
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
                ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            if !record.targets.contains(&acknowledgement.target) {
                return Err(ErasureErrorV1::Unauthorized);
            }
            if record.acknowledgements.iter().any(|existing| {
                existing.obligation == acknowledgement.obligation
                    && existing.owner == acknowledgement.owner
            }) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let admission = record
                .supporting_records
                .retry_admissions
                .last()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let command = destruction_command_reference(request, acknowledgement.target);
            let pair_is_admitted = admission
                .unresolved_obligations()
                .iter()
                .zip(admission.command_identities())
                .any(|(obligation, admitted_command)| {
                    *obligation == acknowledgement.obligation && *admitted_command == command
                });
            if !pair_is_admitted {
                return Err(ErasureErrorV1::Unauthorized);
            }
            let scope = record
                .supporting_records
                .scope_commitment()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let acknowledgement_provenance =
                ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
                    request,
                    command,
                    attempt: admission.reference(),
                    obligation: acknowledgement.obligation,
                    owner: acknowledgement.owner,
                    scope: scope.reference(),
                    outcome: acknowledgement.outcome,
                    evidence: acknowledgement.evidence,
                    policy: admission.policy(),
                    trust: admission.trust(),
                })?;
            self.port.admit_acknowledgement(request, &acknowledgement)?;
            record.acknowledgements.push(acknowledgement);
            record.acknowledgements.sort_unstable();
            record
                .supporting_records
                .acknowledgement_provenance
                .push(acknowledgement_provenance);
            record
                .supporting_records
                .acknowledgement_provenance
                .sort_unstable_by_key(acknowledgement_provenance_ordering_key);
            let state = record.state.clone();
            self.commit(record).map(|()| state)
        })
    }
    /// Commit a receipt after normalizing core-derived fields against this record.
    ///
    /// A terminal retry must reproduce the exact caller-owned evidence admitted
    /// for that receipt. Request identity, terminal state, lifecycle, freeze
    /// position, closure, acknowledgements, owner sets, replay claim, and the
    /// derived receipt digest are normalized from durable coordinator state.
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
                let has_active_attempt = record.supporting_records.retry_admissions.len()
                    == record
                        .supporting_records
                        .attempt_outcomes
                        .len()
                        .saturating_add(1);
                if !has_active_attempt {
                    return Self::normalize_receipt_input(
                        request,
                        self.coordinator,
                        &record,
                        input,
                    )
                    .and_then(|normalized| {
                        if record.receipt_input.as_ref() == Some(&normalized) {
                            Ok(stored)
                        } else {
                            Err(ErasureErrorV1::PolicyConflict)
                        }
                    });
                }
            }
            Self::finalize_record(self, request, &mut record, &input)
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
        if !record.state.lifecycle().is_attempt_terminal() {
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
        sort_inventories(&mut input.inventories);
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        if let Some(receipt) = record.receipt.as_ref() {
            input.policy = receipt.0.policy;
            input.trust = receipt.0.trust;
            input.provenance = receipt.provenance();
        }
        input.receipt_digest = reference_zero();
        Ok(input)
    }

    fn finalize_record(
        &mut self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<ErasureReceiptV1, ErasureErrorV1> {
        Self::prepare_finalization(self, request, record, input)
            .and_then(|(terminal_record, receipt)| self.commit(terminal_record).map(|()| receipt))
    }

    fn attempt_outcome(
        record: &ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
        lifecycle: ErasureLifecycleV1,
        terminal_position: u64,
    ) -> Result<(ErasureAttemptOutcomeV1, Vec<ErasureReferenceV1>), ErasureErrorV1> {
        let acknowledgements = record
            .supporting_records
            .acknowledgement_provenance
            .iter()
            .filter(|provenance| provenance.attempt() == admission.reference())
            .map(ErasureAcknowledgementProvenanceV1::reference)
            .collect::<Vec<_>>();
        let outcome = ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
            request: record.request.reference(),
            attempt: admission.reference(),
            source_receipt: admission.source_receipt(),
            lifecycle,
            selected_obligations: selected_obligations_reference(
                admission.unresolved_obligations(),
            ),
            acknowledgement_inventory: acknowledgement_inventory_reference(&acknowledgements),
            terminal_position,
            policy: admission.policy(),
            trust: admission.trust(),
        })?;
        Ok((outcome, acknowledgements))
    }

    fn receipt_provenance_for_attempt(
        admission: &ErasureRetryAdmissionV1,
        terminal_state: ErasureReferenceV1,
        acknowledgements: &[ErasureReferenceV1],
        issue_position: u64,
    ) -> Result<ErasureReceiptProvenanceV1, ErasureErrorV1> {
        ErasureReceiptProvenanceV1::new(ErasureReceiptProvenanceInputV1 {
            request: admission.request(),
            attempt: admission.reference(),
            attempt_ordinal: admission.attempt_ordinal(),
            predecessor_receipt: admission.source_receipt(),
            terminal_state,
            evidence_set: erasure_evidence_set_reference(acknowledgements),
            policy: admission.policy(),
            trust: admission.trust(),
            issue_position,
        })
    }

    fn prepare_finalization(
        &self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
    ) -> Result<(ErasureCoordinatorRecordV1, ErasureReceiptV1), ErasureErrorV1> {
        if !matches!(
            record.state.lifecycle(),
            ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let admission = record
            .supporting_records
            .retry_admissions
            .last()
            .cloned()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if record.supporting_records.retry_admissions.len()
            != record
                .supporting_records
                .attempt_outcomes
                .len()
                .saturating_add(1)
            || input.issue_position > admission.deadline_position()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let complete = acknowledgements_match_inventory_obligations(
            &input.inventories,
            &record.acknowledgements,
        ) && record
            .acknowledgements
            .iter()
            .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let lifecycle = if complete {
            ErasureLifecycleV1::Complete
        } else {
            ErasureLifecycleV1::PartialFailure
        };
        let (pending_owners, failed_owners) =
            derived_outcome_owners(&input.inventories, &record.acknowledgements)?;
        let replay_claim = weakest_inventory_claim(&input.inventories);
        let freeze_position = record.state.freeze_position();
        let (outcome, acknowledgement_references) =
            Self::attempt_outcome(record, &admission, lifecycle, input.issue_position)?;
        let terminal = record.state.transition(ErasureStateTransitionV1 {
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
            provenance: outcome.reference(),
        })?;
        record.state = terminal;
        let receipt_provenance = Self::receipt_provenance_for_attempt(
            &admission,
            record.state.state_digest(),
            &acknowledgement_references,
            input.issue_position,
        )?;
        let mut normalized =
            Self::normalize_receipt_input(request, self.coordinator, record, input.clone())?;
        normalized.policy = admission.policy();
        normalized.trust = admission.trust();
        normalized.provenance = receipt_provenance.reference();
        self.port.admit_receipt(&normalized)?;
        let receipt = ErasureReceiptV1::new(normalized.clone())?;
        record.receipt_input = Some(normalized);
        record.receipt = Some(receipt.clone());
        record.supporting_records.attempt_outcomes.push(outcome);
        record.supporting_records.receipts.push(receipt.clone());
        record
            .supporting_records
            .receipt_provenance
            .push(receipt_provenance);
        Ok((record.clone(), receipt))
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

    fn reject(
        &mut self,
        request: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::reject(self, request, provenance)
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
        admission: ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::dispatch_attempt(self, request, &admission)
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
    acknowledgement_provenance_from_fields, acknowledgement_provenance_value,
    acknowledgements_are_closure_subset, administrative_resolution_from_fields,
    administrative_resolution_value, attempt_outcome_from_fields, attempt_outcome_value,
    correction_provenance_from_fields, correction_provenance_value, decode_limited, domain_digest,
    encode_canonical, encode_limited, exact_array, freeze_failure_from_fields,
    freeze_failure_value, freeze_is_monotonic, freeze_provenance_from_fields,
    freeze_provenance_value, has_duplicate, has_duplicate_by_target, invalid_owner_sets,
    inventories_exceed_bound, inventories_have_duplicate_targets, inventories_match_closure,
    inventory_categories_match, inventory_transitions_preserve_or_weaken, receipt_core_value,
    receipt_from_fields, receipt_provenance_from_fields, receipt_provenance_value, receipt_value,
    record_from_fields, record_value, reference_zero, request_from_fields, request_value,
    retry_admission_from_fields, retry_admission_value, scope_commitment_from_fields,
    scope_commitment_value, sort_inventories, state_core_value, state_from_fields, state_value,
    strictly_increasing, supporting_records_from_value, supporting_records_value,
    weakest_inventory_claim,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "erasure_tests.rs"]
mod tests;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod erasure_coverage_tests {
    use super::*;

    const fn coordinator() -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([2; 32])
    }

    #[test]
    fn erasure_record_limit_matches_the_public_contract() {
        assert_eq!(ERASURE_COORDINATOR_RECORD_MAX_BYTES, 64 * 1024 * 1024);
    }

    #[test]
    fn supporting_evidence_prefix_rejects_removed_correction_provenance(
    ) -> Result<(), ErasureErrorV1> {
        let correction = ErasureCorrectionProvenanceV1::new(ErasureCorrectionProvenanceInputV1 {
            rejected_request: ErasureReferenceV1::from_digest([3; 32]),
            rejected_terminal_state: ErasureReferenceV1::from_digest([4; 32]),
            correction_reason: ErasureReferenceV1::from_digest([5; 32]),
            authorization_provenance: ErasureReferenceV1::from_digest([6; 32]),
        })?;
        let with_correction = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            correction_provenance: Some(correction),
            ..ErasureSupportingRecordsInputV1::default()
        })?;
        assert!(!with_correction.is_prefix_of(&ErasureSupportingRecordsV1::default()));

        let admission = ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
            request: ErasureReferenceV1::from_digest([7; 32]),
            attempt_ordinal: 0,
            source_receipt: None,
            unresolved_obligations: vec![ErasureReferenceV1::from_digest([8; 32])],
            command_identities: vec![ErasureReferenceV1::from_digest([9; 32])],
            policy: ErasureReferenceV1::from_digest([10; 32]),
            trust: ErasureReferenceV1::from_digest([11; 32]),
            admitted_position: 12,
            deadline_position: 12,
            authorization_provenance: ErasureReferenceV1::from_digest([13; 32]),
        })?;
        let with_admission = ErasureSupportingRecordsV1::new(ErasureSupportingRecordsInputV1 {
            retry_admissions: vec![admission],
            ..ErasureSupportingRecordsInputV1::default()
        })?;
        assert!(!with_admission.is_prefix_of(&ErasureSupportingRecordsV1::default()));
        Ok(())
    }

    #[test]
    fn public_state_chain_verification_rejects_a_missing_predecessor() -> Result<(), ErasureErrorV1>
    {
        struct EmptyResolver;

        impl ErasureStateResolverV1 for EmptyResolver {
            fn resolve_state(
                &self,
                _digest: ErasureReferenceV1,
            ) -> Result<Option<ErasureStateV1>, ErasureErrorV1> {
                Ok(None)
            }
        }

        let submitted = ErasureStateV1::submitted(
            ErasureReferenceV1::from_digest([1; 32]),
            ErasureReferenceV1::from_digest([2; 32]),
            ErasureReferenceV1::from_digest([3; 32]),
        )?;
        let authorized = submitted.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::Authorized,
            freeze_position: None,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            provenance: ErasureReferenceV1::from_digest([4; 32]),
        })?;
        assert_eq!(
            authorized.verify_predecessor_chain(&EmptyResolver),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn independent_supporting_collections_enforce_their_public_bounds() -> Result<(), ErasureErrorV1>
    {
        let acknowledgement =
            ErasureAcknowledgementProvenanceV1::new(ErasureAcknowledgementProvenanceInputV1 {
                request: ErasureReferenceV1::from_digest([1; 32]),
                command: ErasureReferenceV1::from_digest([2; 32]),
                attempt: ErasureReferenceV1::from_digest([3; 32]),
                obligation: ErasureReferenceV1::from_digest([4; 32]),
                owner: ErasureReferenceV1::from_digest([5; 32]),
                scope: ErasureReferenceV1::from_digest([6; 32]),
                outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
                evidence: ErasureReferenceV1::from_digest([7; 32]),
                policy: ErasureReferenceV1::from_digest([8; 32]),
                trust: ErasureReferenceV1::from_digest([9; 32]),
            })?;
        let oversized_acknowledgements = ErasureSupportingRecordsV1 {
            acknowledgement_provenance: vec![acknowledgement; ERASURE_MAX_INVENTORY_RESULTS + 1],
            ..ErasureSupportingRecordsV1::default()
        };
        assert_eq!(
            oversized_acknowledgements.validate(),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut oversized_admission = ErasureRetryAdmissionInputV1 {
            request: ErasureReferenceV1::from_digest([1; 32]),
            attempt_ordinal: 0,
            source_receipt: None,
            unresolved_obligations: vec![
                ErasureReferenceV1::from_digest([2; 32]);
                ERASURE_MAX_INVENTORY_RESULTS + 1
            ],
            command_identities: vec![
                ErasureReferenceV1::from_digest([3; 32]);
                ERASURE_MAX_INVENTORY_RESULTS + 1
            ],
            policy: ErasureReferenceV1::from_digest([4; 32]),
            trust: ErasureReferenceV1::from_digest([5; 32]),
            admitted_position: 10,
            deadline_position: 10,
            authorization_provenance: ErasureReferenceV1::from_digest([6; 32]),
        };
        assert_eq!(
            normalize_retry_admission(&mut oversized_admission),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        Ok(())
    }

    fn transition(
        lifecycle: ErasureLifecycleV1,
        freeze_position: Option<u64>,
        replay_claim: ErasureReplayClaimV1,
        provenance: ErasureReferenceV1,
    ) -> ErasureStateTransitionV1 {
        ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim,
            provenance,
        }
    }

    fn forged_state(
        previous: &ErasureStateV1,
        lifecycle: ErasureLifecycleV1,
        freeze_position: Option<u64>,
        replay_claim: ErasureReplayClaimV1,
        previous_state: Option<ErasureReferenceV1>,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let mut state = previous.clone();
        state.lifecycle = lifecycle;
        state.freeze_position = freeze_position;
        state.pending_owners.clear();
        state.failed_owners.clear();
        state.replay_claim = replay_claim;
        state.previous_state = previous_state;
        state.provenance = ErasureReferenceV1::from_digest([88; 32]);
        state.state_digest = reference_zero();
        state.with_digest()
    }

    struct ReplacementFixtures {
        submitted: ErasureCoordinatorRecordV1,
        authorized: ErasureCoordinatorRecordV1,
        reserved: ErasureCoordinatorRecordV1,
        frozen: ErasureCoordinatorRecordV1,
        intent: ErasureCoordinatorRecordV1,
        dispatched: ErasureCoordinatorRecordV1,
        awaiting: ErasureCoordinatorRecordV1,
        acknowledged: ErasureCoordinatorRecordV1,
        target: ErasureRequiredTargetV1,
    }

    fn replacement_fixtures() -> Result<ReplacementFixtures, ErasureErrorV1> {
        let submitted = tests::record_after_submit()?;
        let authorized_state = submitted.state().transition(transition(
            ErasureLifecycleV1::Authorized,
            None,
            ErasureReplayClaimV1::StructuralOnly,
            ErasureReferenceV1::from_digest([9; 32]),
        ))?;
        let mut authorized_parts = tests::record_parts(&submitted);
        authorized_parts.state = authorized_state;
        authorized_parts.authorize_provenance = Some(ErasureReferenceV1::from_digest([9; 32]));
        let authorized = ErasureCoordinatorRecordV1::from_parts(authorized_parts, coordinator())?;

        let target =
            tests::acknowledgement(1, ErasureAcknowledgementOutcomeV1::Acknowledged).target;
        let mut reserved_parts = tests::record_parts(&authorized);
        reserved_parts.reserved_targets = vec![target];
        let reserved = ErasureCoordinatorRecordV1::from_parts(reserved_parts, coordinator())?;

        let frozen = tests::record_after_freeze(vec![target])?;
        let intent = tests::record_after_dispatch_intent(target)?;
        let awaiting = tests::record_after_dispatch(target)?;
        let admission = awaiting
            .supporting_records()
            .retry_admissions()
            .last()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        let dispatched_state = frozen.state().transition(transition(
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            frozen.state().replay_claim(),
            admission.reference(),
        ))?;
        let mut dispatched_parts = tests::record_parts(&awaiting);
        dispatched_parts.state = dispatched_state;
        let dispatched = ErasureCoordinatorRecordV1::from_parts(dispatched_parts, coordinator())?;
        let acknowledged = tests::record_after_acknowledgement()?;
        Ok(ReplacementFixtures {
            submitted,
            authorized,
            reserved,
            frozen,
            intent,
            dispatched,
            awaiting,
            acknowledged,
            target,
        })
    }

    #[test]
    fn replacement_guards_accept_valid_extensions() -> Result<(), ErasureErrorV1> {
        let fixtures = replacement_fixtures()?;
        assert_eq!(
            fixtures.authorized.validate_replacement(&fixtures.reserved),
            Ok(())
        );
        assert_eq!(
            fixtures.frozen.validate_replacement(&fixtures.intent),
            Ok(())
        );
        assert_eq!(
            fixtures
                .awaiting
                .validate_replacement(&fixtures.acknowledged),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn replacement_guards_reject_identity_and_predecessor_conflicts() -> Result<(), ErasureErrorV1>
    {
        let fixtures = replacement_fixtures()?;
        let mut invalid_reservation_parts = tests::record_parts(&fixtures.reserved);
        invalid_reservation_parts
            .reserved_targets
            .push(ErasureRequiredTargetV1 {
                artifact_digest: ErasureReferenceV1::from_digest([5; 32]),
                ..fixtures.target
            });
        let invalid_reservation =
            ErasureCoordinatorRecordV1::from_parts(invalid_reservation_parts, coordinator())?;
        assert_eq!(
            fixtures.reserved.validate_replacement(&invalid_reservation),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut changed_request_input = tests::request_input(vec![
            ErasureReferenceV1::from_digest([8; 32]),
            ErasureReferenceV1::from_digest([7; 32]),
        ]);
        changed_request_input.request = ErasureReferenceV1::from_digest([99; 32]);
        let changed_request = ErasureRequestV1::new(changed_request_input)?;
        let changed_request_state = ErasureStateV1::submitted(
            changed_request.reference(),
            coordinator(),
            ErasureReferenceV1::from_digest([3; 32]),
        )?;
        let changed_request_record = ErasureCoordinatorRecordV1::from_parts(
            ErasureCoordinatorRecordPartsV1 {
                request: changed_request,
                state: changed_request_state,
                reserved_targets: Vec::new(),
                targets: Vec::new(),
                acknowledgements: Vec::new(),
                receipt: None,
                receipt_input: None,
                authorize_provenance: None,
                freeze_provenance: None,
                freeze_admission: None,
                dispatch_provenance: None,
                supporting_records: ErasureSupportingRecordsV1::default(),
            },
            coordinator(),
        )?;
        assert_eq!(
            fixtures
                .submitted
                .validate_replacement(&changed_request_record),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut wrong_predecessor_state = fixtures.frozen.state.clone();
        wrong_predecessor_state.previous_state = Some(ErasureReferenceV1::from_digest([99; 32]));
        wrong_predecessor_state.state_digest = reference_zero();
        let mut wrong_predecessor_parts = tests::record_parts(&fixtures.frozen);
        wrong_predecessor_parts.state = wrong_predecessor_state.with_digest()?;
        let wrong_predecessor =
            ErasureCoordinatorRecordV1::from_parts(wrong_predecessor_parts, coordinator())?;
        assert_eq!(
            fixtures.frozen.validate_replacement(&wrong_predecessor),
            Err(ErasureErrorV1::PolicyConflict)
        );
        Ok(())
    }

    #[test]
    fn replacement_guards_reject_claim_and_provenance_conflicts() -> Result<(), ErasureErrorV1> {
        let fixtures = replacement_fixtures()?;
        let decreased_state = forged_state(
            &fixtures.frozen.state,
            ErasureLifecycleV1::DestructionDispatched,
            Some(9),
            ErasureReplayClaimV1::StructuralOnly,
            Some(fixtures.frozen.state.state_digest()),
        )?;
        let mut decreased_parts = tests::record_parts(&fixtures.frozen);
        decreased_parts.state = decreased_state;
        decreased_parts.dispatch_provenance = Some(ErasureReferenceV1::from_digest([10; 32]));
        decreased_parts.freeze_admission = Some(ErasureFreezeAdmissionV1 {
            freeze_position: 9,
            provenance: ErasureReferenceV1::from_digest([9; 32]),
            target_closure: target_closure_digest(&[fixtures.target]),
        });
        assert_eq!(
            ErasureCoordinatorRecordV1::from_parts(decreased_parts, coordinator()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let upgraded_state = forged_state(
            &fixtures.frozen.state,
            ErasureLifecycleV1::DestructionDispatched,
            Some(10),
            ErasureReplayClaimV1::Exact,
            Some(fixtures.frozen.state.state_digest()),
        )?;
        let mut upgraded_parts = tests::record_parts(&fixtures.frozen);
        upgraded_parts.state = upgraded_state;
        upgraded_parts.dispatch_provenance = Some(ErasureReferenceV1::from_digest([10; 32]));
        assert_eq!(
            ErasureCoordinatorRecordV1::from_parts(upgraded_parts, coordinator()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );

        let mut changed_authorization_parts = tests::record_parts(&fixtures.frozen);
        changed_authorization_parts.state = fixtures.dispatched.state.clone();
        changed_authorization_parts.authorize_provenance =
            Some(ErasureReferenceV1::from_digest([99; 32]));
        changed_authorization_parts.dispatch_provenance = fixtures.dispatched.dispatch_provenance;
        changed_authorization_parts.supporting_records =
            fixtures.dispatched.supporting_records.clone();
        let changed_authorization =
            ErasureCoordinatorRecordV1::from_parts(changed_authorization_parts, coordinator())?;
        assert_eq!(
            fixtures
                .dispatched
                .validate_replacement(&changed_authorization),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut changed_freeze_parts = tests::record_parts(&fixtures.dispatched);
        changed_freeze_parts.freeze_provenance = Some(ErasureReferenceV1::from_digest([99; 32]));
        changed_freeze_parts.freeze_admission = Some(ErasureFreezeAdmissionV1 {
            freeze_position: 10,
            provenance: ErasureReferenceV1::from_digest([99; 32]),
            target_closure: target_closure_digest(&[fixtures.target]),
        });
        assert_eq!(
            ErasureCoordinatorRecordV1::from_parts(changed_freeze_parts, coordinator()),
            Err(ErasureErrorV1::PolicyConflict)
        );

        let mut changed_dispatch_parts = tests::record_parts(&fixtures.awaiting);
        changed_dispatch_parts.dispatch_provenance =
            Some(ErasureReferenceV1::from_digest([99; 32]));
        assert_eq!(
            ErasureCoordinatorRecordV1::from_parts(changed_dispatch_parts, coordinator()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn terminal_receipt_claim_is_bound_to_terminal_state() -> Result<(), ErasureErrorV1> {
        let complete = tests::complete_record()?;
        let mut parts = tests::record_parts(&complete);
        let mut terminal_state = complete.state().clone();
        terminal_state.replay_claim = ErasureReplayClaimV1::Exact;
        terminal_state.state_digest = reference_zero();
        let terminal_state = terminal_state.with_digest()?;
        parts.state = terminal_state.clone();
        let input = parts
            .receipt_input
            .as_mut()
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        input.terminal_state = terminal_state.state_digest();
        parts.receipt = Some(ErasureReceiptV1::new(input.clone())?);
        assert_eq!(
            ErasureCoordinatorRecordV1::from_parts(parts, coordinator()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        Ok(())
    }

    #[test]
    fn destruction_command_identity_is_stable_across_provenance_retries() {
        let target = ErasureRequiredTargetV1 {
            artifact_class: ErasureArtifactClassV1::TimelineReplay,
            artifact_digest: ErasureReferenceV1::from_digest([1; 32]),
            key_role: ErasureKeyRoleV1::DataEncryption,
            key_digest: ErasureReferenceV1::from_digest([2; 32]),
            replica_set: ErasureReferenceV1::from_digest([3; 32]),
            replica_id: ErasureReferenceV1::from_digest([4; 32]),
        };
        let first = ErasureDestructionCommandV1::new(reference_zero(), target, reference_zero());
        let retry = ErasureDestructionCommandV1::new(
            reference_zero(),
            target,
            ErasureReferenceV1::from_digest([99; 32]),
        );
        assert_eq!(first.command, retry.command);
        assert_eq!(
            first.command,
            destruction_command_reference(reference_zero(), target)
        );
        assert_eq!(first.target, target);
        let variants = [
            ErasureRequiredTargetV1 {
                artifact_class: ErasureArtifactClassV1::ReproManifest,
                ..target
            },
            ErasureRequiredTargetV1 {
                artifact_digest: ErasureReferenceV1::from_digest([5; 32]),
                ..target
            },
            ErasureRequiredTargetV1 {
                key_role: ErasureKeyRoleV1::Signing,
                ..target
            },
            ErasureRequiredTargetV1 {
                key_digest: ErasureReferenceV1::from_digest([6; 32]),
                ..target
            },
            ErasureRequiredTargetV1 {
                replica_set: ErasureReferenceV1::from_digest([7; 32]),
                ..target
            },
            ErasureRequiredTargetV1 {
                replica_id: ErasureReferenceV1::from_digest([8; 32]),
                ..target
            },
        ];
        for variant in variants {
            assert_ne!(
                first.command,
                destruction_command_reference(reference_zero(), variant)
            );
        }
        assert_ne!(
            first.command,
            destruction_command_reference(ErasureReferenceV1::from_digest([2; 32]), target)
        );
    }

    #[test]
    fn canonical_record_decoder_rejects_noncanonical_and_trailing_bytes(
    ) -> Result<(), ErasureErrorV1> {
        let record = tests::complete_record()?;
        let bytes = record.to_canonical_cbor()?;

        let mut noncanonical = bytes.clone();
        assert_eq!(
            &noncanonical[..8],
            &[0x8d, 0x65, b'E', b'R', b'C', b'R', b'1', 0x01]
        );
        noncanonical[7] = 0x18;
        noncanonical.insert(8, 1);
        assert_eq!(
            ErasureCoordinatorRecordV1::from_canonical_cbor(&noncanonical),
            Err(ErasureErrorV1::InvalidEncoding)
        );

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ErasureCoordinatorRecordV1::from_canonical_cbor(&trailing),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        Ok(())
    }
}
