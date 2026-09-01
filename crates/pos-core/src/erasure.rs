//! ADR-060's payload-free ERQ1, ERS1, and ERC1 public contracts.
//!
//! This module deliberately excludes storage implementations, key destruction,
//! artifact work, backup inventory, and replay evaluation. Those operations
//! belong to the adapters and follow-up tickets named by ADR-060.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

const VERSION: u64 = 1;
const ERQ1: &str = "ERQ1";
const ERS1: &str = "ERS1";
const ERC1: &str = "ERC1";
const ERCR1: &str = "ERCR1";
const ERCRP1: &str = "ERCRP1";
const ERASURE_INVENTORY_CATEGORY_COUNT: usize = ErasureInventoryCategoryV1::CANONICAL.len();

/// Largest encoded ERQ1 or ERS1 accepted by V1.
pub const ERASURE_REQUEST_OR_STATE_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded ERC1 accepted by V1.
pub const ERASURE_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest aggregate ERCR1 envelope or normalized persistence manifest.
pub const ERASURE_COORDINATOR_RECORD_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Largest selector or owner collection accepted by V1.
pub const ERASURE_MAX_REFERENCES: usize = 4_096;
/// Largest number of entries in each ERC1 inventory.
pub const ERASURE_MAX_INVENTORY_RESULTS: usize = 65_536;
/// Largest canonical target closure admitted for one ERQ1.
pub const ERASURE_MAX_TARGETS: usize = 65_536;
/// Largest number of frozen obligations in one category.
pub const ERASURE_MAX_OBLIGATIONS_PER_CATEGORY: usize = 65_536;
/// Largest number of frozen obligations across all categories.
pub const ERASURE_MAX_OBLIGATIONS: usize = 262_144;
/// Largest number of immutable scope extensions retained for one ERQ1.
pub const ERASURE_MAX_SCOPE_EXTENSIONS: usize = 65_536;
/// Largest encoded portable supporting record, except explicitly bounded large ledgers.
pub const ERASURE_PORTABLE_RECORD_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded immutable scope commitment or scope-extension ledger.
pub const ERASURE_SCOPE_LEDGER_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest encoded immutable obligation-set record.
pub const ERASURE_OBLIGATION_SET_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest encoded freeze-admission or authorization-evidence record.
pub const ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest encoded retry-admission record.
pub const ERASURE_RETRY_ADMISSION_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Independent ordinal ceiling for attempt outcomes or ERC1 receipts.
pub const ERASURE_MAX_ATTEMPT_OUTCOMES: usize = 4_096;
/// Maximum number of administrative resolutions per ERQ1.
pub const ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS: usize = 4_096;

const fn target_count_is_bounded(count: usize) -> bool {
    count <= ERASURE_MAX_TARGETS
}

const fn applicability_matrix_cardinality_is_valid(count: usize) -> bool {
    count != 0
        && count <= ERASURE_MAX_OBLIGATIONS
        && count.is_multiple_of(ERASURE_INVENTORY_CATEGORY_COUNT)
}

const fn obligation_count_is_bounded(count: usize) -> bool {
    count <= ERASURE_MAX_OBLIGATIONS
}

const fn category_obligation_count_is_bounded(count: usize) -> bool {
    count <= ERASURE_MAX_OBLIGATIONS_PER_CATEGORY
}

const fn scope_extension_count_is_bounded(count: usize) -> bool {
    count <= ERASURE_MAX_SCOPE_EXTENSIONS
}

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
/// Domain tag for canonical freeze-admission applicability evidence.
pub const ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1: &str = "ERFA1";
/// Domain tag for the exact freeze-admission authorization preimage.
pub const ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1: &str = "ERFA1-AUTH";
/// Domain tag for retained host authorization evidence.
pub const ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1: &str = "ERFAA1";
/// Domain tag for immutable access-freeze failure records.
pub const ERASURE_FREEZE_FAILURE_TAG_V1: &str = "ERFF1";
/// Domain tag for a pre-authorization rejection record.
pub const ERASURE_AUTHORIZATION_REJECTION_TAG_V1: &str = "ERAJ1";
/// Domain tag for immutable category/target/owner obligations.
pub const ERASURE_OBLIGATION_TAG_V1: &str = "ERO1";
/// Domain tag for an immutable frozen obligation set.
pub const ERASURE_OBLIGATION_SET_TAG_V1: &str = "EROS1";
/// Domain tag for immutable future-Fork scope extensions.
pub const ERASURE_SCOPE_EXTENSION_TAG_V1: &str = "ERSE1";
/// Domain tag for immutable scope-extension ledgers.
pub const ERASURE_SCOPE_EXTENSION_LEDGER_TAG_V1: &str = "ERSEL1";

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
    /// Canonical Timeline/Fork members resolved by the host.
    pub scope_members: Vec<ErasureReferenceV1>,
    /// Digest of the exact frozen target closure.
    pub target_closure: ErasureReferenceV1,
    /// Immutable future-Fork lineage-expansion rule admitted before freeze.
    ///
    /// `None` means that the initial affected scope is the entire effective
    /// scope for this ERQ1. A mutable extension head is deliberately not part
    /// of this immutable content-addressed object.
    pub lineage_rule: Option<ErasureReferenceV1>,
}

/// Content-addressed resolved scope frozen before destructive work begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeCommitmentV1 {
    input: ErasureScopeCommitmentInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureScopeCommitmentV1 {
    /// Validate and content-address one resolved scope.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an empty, duplicate, or oversized scope.
    pub fn new(input: ErasureScopeCommitmentInputV1) -> Result<Self, ErasureErrorV1> {
        if input.scope_members.is_empty()
            || input.scope_members.len() > ERASURE_MAX_SCOPE_EXTENSIONS
            || !strictly_increasing(&input.scope_members)
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
    /// Return canonical Timeline/Fork members.
    #[must_use]
    pub fn scope_members(&self) -> &[ErasureReferenceV1] {
        &self.input.scope_members
    }
    /// Return the frozen target-closure digest.
    #[must_use]
    pub const fn target_closure(&self) -> ErasureReferenceV1 {
        self.input.target_closure
    }
    /// Return the immutable future-Fork lineage rule, when admitted.
    #[must_use]
    pub const fn lineage_rule(&self) -> Option<ErasureReferenceV1> {
        self.input.lineage_rule
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
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
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
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
            ERASURE_MAX_SCOPE_EXTENSIONS,
        )
        .and_then(|value| exact_array(&value, 6).and_then(scope_commitment_from_fields))
    }
    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_commitment_value(&self),
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
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

/// Closed policy-applicability decision for one category and target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureApplicabilityDecisionV1 {
    /// Policy determined that no obligation applies.
    Inapplicable,
    /// Policy admitted one category-scoped owner obligation.
    Applicable,
}

impl ErasureApplicabilityDecisionV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Inapplicable => 0,
            Self::Applicable => 1,
        }
    }

    const fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Inapplicable),
            1 => Ok(Self::Applicable),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// One canonical row in the complete category-by-target applicability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeApplicabilityRowV1 {
    category: ErasureInventoryCategoryV1,
    target_index: u64,
    decision: ErasureApplicabilityDecisionV1,
    owner: Option<ErasureReferenceV1>,
}

impl ErasureFreezeApplicabilityRowV1 {
    /// Construct one exact applicability row.
    ///
    /// # Errors
    ///
    /// Returns a scope error unless owner presence exactly matches the decision.
    pub const fn new(
        category: ErasureInventoryCategoryV1,
        target_index: u64,
        decision: ErasureApplicabilityDecisionV1,
        owner: Option<ErasureReferenceV1>,
    ) -> Result<Self, ErasureErrorV1> {
        if matches!(
            (decision, owner),
            (ErasureApplicabilityDecisionV1::Applicable, Some(_))
                | (ErasureApplicabilityDecisionV1::Inapplicable, None)
        ) {
            Ok(Self {
                category,
                target_index,
                decision,
                owner,
            })
        } else {
            Err(ErasureErrorV1::ScopeInvalid)
        }
    }

    /// Return the closed obligation category.
    #[must_use]
    pub const fn category(self) -> ErasureInventoryCategoryV1 {
        self.category
    }

    /// Return the index into the canonical target closure.
    #[must_use]
    pub const fn target_index(self) -> u64 {
        self.target_index
    }

    /// Return the policy-applicability decision.
    #[must_use]
    pub const fn decision(self) -> ErasureApplicabilityDecisionV1 {
        self.decision
    }

    /// Return the category-scoped owner for an applicable row.
    #[must_use]
    pub const fn owner(self) -> Option<ErasureReferenceV1> {
        self.owner
    }
}

/// Construction fields for retained #187-owned authorization evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAuthorizationEvidenceInputV1 {
    /// Digest of the exact domain-separated ERFA1 authorization preimage.
    pub admission_body_digest: ErasureReferenceV1,
    /// Policy revision under which the evidence was admitted.
    pub policy: ErasureReferenceV1,
    /// Trust revision under which the evidence was admitted.
    pub trust: ErasureReferenceV1,
    /// Canonical proof or signature material interpreted by #187.
    pub evidence: Vec<u8>,
}

/// Retained canonical evidence authenticating one freeze-admission body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAuthorizationEvidenceV1 {
    input: ErasureFreezeAuthorizationEvidenceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureFreezeAuthorizationEvidenceV1 {
    /// Construct and content-address retained host authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for empty or oversized proof material.
    pub fn new(input: ErasureFreezeAuthorizationEvidenceInputV1) -> Result<Self, ErasureErrorV1> {
        if input.evidence.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the authenticated ERFA1 authorization-body digest.
    #[must_use]
    pub const fn admission_body_digest(&self) -> ErasureReferenceV1 {
        self.input.admission_body_digest
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

    /// Return the opaque canonical #187 evidence bytes.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.input.evidence
    }

    /// Return this evidence object's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Verify that this evidence names the exact supplied admission body.
    ///
    /// This verifies the canonical digest binding only. The host-owned
    /// [`ErasureFreezeAuthorizationVerifierV1`] remains responsible for
    /// interpreting the retained policy, trust, and proof material.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization error when the body digest differs, or
    /// propagates a canonical-encoding error from the admission body.
    pub fn verify_admission_body_binding(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        (self.admission_body_digest() == admission.authorization_body_digest()?)
            .then_some(())
            .ok_or(ErasureErrorV1::Unauthorized)
    }

    /// Encode the exact retained authorization-evidence object.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds 16 MiB.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_authorization_evidence_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
    }

    /// Decode one exact retained authorization-evidence object.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| {
            exact_array(&value, 6).and_then(freeze_authorization_evidence_from_fields)
        })
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_authorization_evidence_value(&self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for the canonical freeze-admission applicability object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionEvidenceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Resolved scope-commitment address.
    pub scope_commitment: ErasureReferenceV1,
    /// Frozen obligation-set address.
    pub obligation_set: ErasureReferenceV1,
    /// Complete category-major applicability matrix.
    pub applicability_matrix: Vec<ErasureFreezeApplicabilityRowV1>,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Pinned policy revision.
    pub policy: ErasureReferenceV1,
    /// Pinned trust revision.
    pub trust: ErasureReferenceV1,
    /// Retained authorization-evidence content address.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Complete, content-addressed freeze-admission applicability evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureFreezeAdmissionEvidenceV1 {
    input: ErasureFreezeAdmissionEvidenceInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureFreezeAdmissionEvidenceV1 {
    /// Construct and validate one exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a scope error unless the matrix is complete and category-major.
    pub fn new(input: ErasureFreezeAdmissionEvidenceInputV1) -> Result<Self, ErasureErrorV1> {
        validate_applicability_matrix(&input.applicability_matrix)?;
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

    /// Return the resolved scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return the frozen obligation set.
    #[must_use]
    pub const fn obligation_set(&self) -> ErasureReferenceV1 {
        self.input.obligation_set
    }

    /// Return the complete category-major applicability matrix.
    #[must_use]
    pub fn applicability_matrix(&self) -> &[ErasureFreezeApplicabilityRowV1] {
        &self.input.applicability_matrix
    }

    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
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

    /// Return the retained authorization-evidence address.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return the exact domain-separated authorization-body digest.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the canonical preimage exceeds 16 MiB.
    pub fn authorization_body_digest(&self) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_authorization_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| {
            ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1,
                &bytes,
            ))
        })
    }

    /// Return this admission object's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds 16 MiB.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_evidence_value(self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
    }

    /// Decode one exact `ERFA1` object.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| exact_array(&value, 10).and_then(freeze_admission_evidence_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &freeze_admission_evidence_value(&self),
            ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

fn validate_applicability_matrix(
    matrix: &[ErasureFreezeApplicabilityRowV1],
) -> Result<(), ErasureErrorV1> {
    if !applicability_matrix_cardinality_is_valid(matrix.len()) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let target_count = matrix.len() / ERASURE_INVENTORY_CATEGORY_COUNT;
    for category in ErasureInventoryCategoryV1::CANONICAL {
        let offset = category.index() * target_count;
        for (target_index, row) in matrix[offset..offset + target_count].iter().enumerate() {
            if row.category() != category || row.target_index() != target_index as u64 {
                return Err(ErasureErrorV1::ScopeInvalid);
            }
        }
    }
    Ok(())
}

/// Construction fields for immutable access-freeze provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureFreezeProvenanceInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Scope commitment frozen by this operation.
    pub scope_commitment: ErasureReferenceV1,
    /// Frozen policy-selected obligation set.
    pub obligation_set: ErasureReferenceV1,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Host-authenticated freeze-admission evidence.
    pub host_evidence: ErasureReferenceV1,
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
    /// Return the frozen obligation-set commitment.
    #[must_use]
    pub const fn obligation_set(&self) -> ErasureReferenceV1 {
        self.input.obligation_set
    }
    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
    }
    /// Return host-authenticated freeze-admission evidence.
    #[must_use]
    pub const fn host_evidence(&self) -> ErasureReferenceV1 {
        self.input.host_evidence
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

/// Construction fields for a rejection that occurs before scope/freeze work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorizationRejectionInputV1 {
    /// ERQ1 digest.
    pub request: ErasureReferenceV1,
    /// Host-authenticated authorization or policy rejection evidence.
    pub authorization_provenance: ErasureReferenceV1,
}

/// Content-addressed evidence for a pre-authorization rejection.
///
/// This is intentionally distinct from [`ErasureFreezeFailureV1`]: an
/// authorization/policy rejection did not resolve scope or attempt a freeze,
/// while a scope/freeze rejection must carry canonical failure provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAuthorizationRejectionV1 {
    input: ErasureAuthorizationRejectionInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureAuthorizationRejectionV1 {
    /// Construct and content-address a pre-authorization rejection.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureAuthorizationRejectionInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the rejected ERQ1 digest.
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.input.request
    }

    /// Return host-authenticated rejection evidence.
    #[must_use]
    pub const fn authorization_provenance(&self) -> ErasureReferenceV1 {
        self.input.authorization_provenance
    }

    /// Return this record's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact-length deterministic record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &authorization_rejection_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode one canonical pre-authorization rejection record.
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
        .and_then(|value| exact_array(&value, 4).and_then(authorization_rejection_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &authorization_rejection_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_AUTHORIZATION_REJECTION_TAG_V1,
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
            ERASURE_MAX_OBLIGATIONS,
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
    authorization_rejection: Option<ErasureAuthorizationRejectionV1>,
    scope_commitment: Option<ErasureScopeCommitmentV1>,
    freeze_admission_evidence: Option<ErasureFreezeAdmissionEvidenceV1>,
    freeze_authorization_evidence: Option<ErasureFreezeAuthorizationEvidenceV1>,
    freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    freeze_failure: Option<ErasureFreezeFailureV1>,
    obligations: Vec<ErasureObligationV1>,
    obligation_set: Option<ErasureObligationSetV1>,
    scope_extensions: Vec<ErasureScopeExtensionV1>,
    scope_extension_ledgers: Vec<ErasureScopeExtensionLedgerV1>,
    retry_admissions: Vec<ErasureRetryAdmissionV1>,
    acknowledgement_provenance: Vec<ErasureAcknowledgementProvenanceV1>,
    attempt_outcomes: Vec<ErasureAttemptOutcomeV1>,
    receipts: Vec<ErasureReceiptV1>,
    receipt_provenance: Vec<ErasureReceiptProvenanceV1>,
    administrative_resolutions: Vec<ErasureAdministrativeResolutionV1>,
}

type ErasureObligationOwnerV1 = (ErasureReferenceV1, ErasureReferenceV1);
type ErasureSelectedPositiveProvenanceV1<'a> = (
    (u64, ErasureReferenceV1),
    &'a ErasureAcknowledgementProvenanceV1,
);
type ErasurePositiveProvenanceIndexV1<'a> =
    BTreeMap<ErasureObligationOwnerV1, ErasureSelectedPositiveProvenanceV1<'a>>;

struct ErasureEvidenceIndex<'a> {
    obligations: BTreeMap<ErasureReferenceV1, &'a ErasureObligationV1>,
    admissions: BTreeMap<ErasureReferenceV1, &'a ErasureRetryAdmissionV1>,
    admitted_commands: BTreeSet<(ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1)>,
    provenance_by_attempt:
        BTreeMap<ErasureReferenceV1, Vec<&'a ErasureAcknowledgementProvenanceV1>>,
    earliest_positive: ErasurePositiveProvenanceIndexV1<'a>,
    current_provenance: BTreeMap<
        (ErasureReferenceV1, ErasureReferenceV1, ErasureReferenceV1),
        &'a ErasureAcknowledgementProvenanceV1,
    >,
}

impl<'a> ErasureEvidenceIndex<'a> {
    fn new(records: &'a ErasureSupportingRecordsV1) -> Self {
        let obligations = records
            .obligations
            .iter()
            .map(|obligation| (obligation.reference(), obligation))
            .collect::<BTreeMap<_, _>>();
        let admissions = records
            .retry_admissions
            .iter()
            .map(|admission| (admission.reference(), admission))
            .collect::<BTreeMap<_, _>>();
        let admitted_commands = records
            .retry_admissions
            .iter()
            .flat_map(|admission| {
                admission
                    .unresolved_obligations()
                    .iter()
                    .copied()
                    .zip(admission.command_identities().iter().copied())
                    .map(|(obligation, command)| (admission.reference(), obligation, command))
            })
            .collect();
        let mut provenance_by_attempt = BTreeMap::<_, Vec<_>>::new();
        let mut earliest_positive = BTreeMap::new();
        let mut current_provenance = BTreeMap::new();
        for provenance in &records.acknowledgement_provenance {
            provenance_by_attempt
                .entry(provenance.attempt())
                .or_default()
                .push(provenance);
            current_provenance
                .entry((
                    provenance.attempt(),
                    provenance.obligation(),
                    provenance.owner(),
                ))
                .or_insert(provenance);
            if provenance.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged {
                let Some(admission) = admissions.get(&provenance.attempt()) else {
                    continue;
                };
                let candidate = (admission.attempt_ordinal(), provenance.reference());
                let entry = earliest_positive
                    .entry((provenance.obligation(), provenance.owner()))
                    .or_insert((candidate, provenance));
                if candidate < entry.0 {
                    *entry = (candidate, provenance);
                }
            }
        }
        Self {
            obligations,
            admissions,
            admitted_commands,
            provenance_by_attempt,
            earliest_positive,
            current_provenance,
        }
    }

    fn effective_provenance(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<(
        &'a ErasureObligationV1,
        &'a ErasureAcknowledgementProvenanceV1,
    )> {
        self.obligations
            .values()
            .filter_map(|obligation| {
                let identity = (obligation.reference(), obligation.owner());
                self.earliest_positive
                    .get(&identity)
                    .filter(|((ordinal, _), _)| *ordinal <= admission.attempt_ordinal())
                    .map(|(_, provenance)| (*obligation, *provenance))
                    .or_else(|| {
                        self.current_provenance
                            .get(&(
                                admission.reference(),
                                obligation.reference(),
                                obligation.owner(),
                            ))
                            .map(|provenance| (*obligation, *provenance))
                    })
            })
            .collect()
    }

    fn advance_effective_references(
        &self,
        admission: &ErasureRetryAdmissionV1,
        carried: &mut ErasurePositiveProvenanceIndexV1<'a>,
    ) -> Vec<ErasureReferenceV1> {
        let mut current = BTreeMap::new();
        for provenance in self
            .provenance_by_attempt
            .get(&admission.reference())
            .into_iter()
            .flatten()
        {
            let provenance = *provenance;
            let Some(obligation) = self.obligations.get(&provenance.obligation()) else {
                continue;
            };
            if obligation.owner() != provenance.owner() {
                continue;
            }
            let identity = (obligation.reference(), obligation.owner());
            if provenance.outcome() == ErasureAcknowledgementOutcomeV1::Acknowledged {
                let candidate = (admission.attempt_ordinal(), provenance.reference());
                let entry = carried.entry(identity).or_insert((candidate, provenance));
                if candidate < entry.0 {
                    *entry = (candidate, provenance);
                }
            } else if !carried.contains_key(&identity) {
                current.entry(identity).or_insert(provenance);
            }
        }
        carried
            .values()
            .map(|(_, provenance)| provenance.reference())
            .chain(current.values().map(|provenance| provenance.reference()))
            .collect()
    }
}

/// Construction fields for [`ErasureSupportingRecordsV1`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErasureSupportingRecordsInputV1 {
    /// Provenance linking a corrected ERQ1 to a rejected predecessor.
    pub correction_provenance: Option<ErasureCorrectionProvenanceV1>,
    /// Canonical evidence for a rejection before scope/freeze work.
    pub authorization_rejection: Option<ErasureAuthorizationRejectionV1>,
    /// Immutable resolved scope, once freeze resolution succeeds.
    pub scope_commitment: Option<ErasureScopeCommitmentV1>,
    /// Complete canonical category-by-target freeze-admission evidence.
    pub freeze_admission_evidence: Option<ErasureFreezeAdmissionEvidenceV1>,
    /// Retained #187-owned authorization proof for the admission body.
    pub freeze_authorization_evidence: Option<ErasureFreezeAuthorizationEvidenceV1>,
    /// Immutable successful freeze evidence.
    pub freeze_provenance: Option<ErasureFreezeProvenanceV1>,
    /// Immutable scope/freeze failure evidence for an authorized rejection.
    pub freeze_failure: Option<ErasureFreezeFailureV1>,
    /// Immutable policy-selected category/target/owner obligations.
    pub obligations: Vec<ErasureObligationV1>,
    /// Immutable set of policy-admitted obligation references.
    pub obligation_set: Option<ErasureObligationSetV1>,
    /// Append-only future-Fork scope-extension objects.
    pub scope_extensions: Vec<ErasureScopeExtensionV1>,
    /// Immutable extension-ledger snapshots from the empty root onward.
    pub scope_extension_ledgers: Vec<ErasureScopeExtensionLedgerV1>,
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
    /// Returns a closed error when this optional aggregate envelope exceeds
    /// the coordinator bound. Durable adapters use normalized evidence.
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
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| supporting_records_from_value(&value))
    }

    /// Validate one complete immutable evidence ledger.
    ///
    /// # Errors
    ///
    /// Returns a closed policy or provenance error for a fork, gap, mismatched
    /// request, attempt, receipt, or bounded collection.
    pub fn new(input: ErasureSupportingRecordsInputV1) -> Result<Self, ErasureErrorV1> {
        Self::from_canonical_input(input)
    }

    pub(super) fn from_canonical_input(
        input: ErasureSupportingRecordsInputV1,
    ) -> Result<Self, ErasureErrorV1> {
        let records = Self {
            correction_provenance: input.correction_provenance,
            authorization_rejection: input.authorization_rejection,
            scope_commitment: input.scope_commitment,
            freeze_admission_evidence: input.freeze_admission_evidence,
            freeze_authorization_evidence: input.freeze_authorization_evidence,
            freeze_provenance: input.freeze_provenance,
            freeze_failure: input.freeze_failure,
            obligations: input.obligations,
            obligation_set: input.obligation_set,
            scope_extensions: input.scope_extensions,
            scope_extension_ledgers: input.scope_extension_ledgers,
            retry_admissions: input.retry_admissions,
            acknowledgement_provenance: input.acknowledgement_provenance,
            attempt_outcomes: input.attempt_outcomes,
            receipts: input.receipts,
            receipt_provenance: input.receipt_provenance,
            administrative_resolutions: input.administrative_resolutions,
        };
        records.validate().map(|()| records)
    }

    /// Return correction provenance, when this ERQ1 replaces a rejection.
    #[must_use]
    pub const fn correction_provenance(&self) -> Option<&ErasureCorrectionProvenanceV1> {
        self.correction_provenance.as_ref()
    }

    /// Return canonical pre-authorization rejection evidence, when present.
    #[must_use]
    pub const fn authorization_rejection(&self) -> Option<ErasureAuthorizationRejectionV1> {
        self.authorization_rejection
    }

    /// Return the immutable resolved scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> Option<&ErasureScopeCommitmentV1> {
        self.scope_commitment.as_ref()
    }

    /// Return complete freeze-admission applicability evidence.
    #[must_use]
    pub const fn freeze_admission_evidence(&self) -> Option<&ErasureFreezeAdmissionEvidenceV1> {
        self.freeze_admission_evidence.as_ref()
    }

    /// Return retained host authorization evidence for the freeze admission.
    #[must_use]
    pub const fn freeze_authorization_evidence(
        &self,
    ) -> Option<&ErasureFreezeAuthorizationEvidenceV1> {
        self.freeze_authorization_evidence.as_ref()
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

    /// Return immutable category/target/owner obligations.
    #[must_use]
    pub fn obligations(&self) -> &[ErasureObligationV1] {
        &self.obligations
    }

    /// Return the frozen obligation-reference set, when access froze.
    #[must_use]
    pub const fn obligation_set(&self) -> Option<&ErasureObligationSetV1> {
        self.obligation_set.as_ref()
    }

    /// Return immutable future-Fork scope extensions.
    #[must_use]
    pub fn scope_extensions(&self) -> &[ErasureScopeExtensionV1] {
        &self.scope_extensions
    }

    /// Return immutable extension-ledger snapshots.
    #[must_use]
    pub fn scope_extension_ledgers(&self) -> &[ErasureScopeExtensionLedgerV1] {
        &self.scope_extension_ledgers
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

    fn persistence_evidence(&self) -> Result<Vec<(ErasureReferenceV1, Vec<u8>)>, ErasureErrorV1> {
        let mut evidence = Vec::new();
        macro_rules! push_optional {
            ($value:expr_2021) => {
                if let Some(value) = $value {
                    evidence.push((value.reference(), value.to_canonical_cbor()?));
                }
            };
        }
        macro_rules! push_records {
            ($values:expr_2021) => {
                for value in $values {
                    evidence.push((value.reference(), value.to_canonical_cbor()?));
                }
            };
        }

        push_optional!(self.correction_provenance.as_ref());
        push_optional!(self.authorization_rejection.as_ref());
        push_optional!(self.scope_commitment.as_ref());
        push_optional!(self.freeze_admission_evidence.as_ref());
        push_optional!(self.freeze_authorization_evidence.as_ref());
        push_optional!(self.freeze_provenance.as_ref());
        push_optional!(self.freeze_failure.as_ref());
        push_records!(&self.obligations);
        push_optional!(self.obligation_set.as_ref());
        push_records!(&self.scope_extensions);
        push_records!(&self.scope_extension_ledgers);
        push_records!(&self.retry_admissions);
        push_records!(&self.acknowledgement_provenance);
        push_records!(&self.attempt_outcomes);
        for receipt in &self.receipts {
            evidence.push((receipt.receipt_digest(), receipt.to_canonical_cbor()?));
        }
        push_records!(&self.receipt_provenance);
        push_records!(&self.administrative_resolutions);
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), ErasureErrorV1> {
        if self.authorization_rejection.is_some() && self.freeze_failure.is_some() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.authorization_rejection.is_some()
            && (self.scope_commitment.is_some()
                || self.freeze_admission_evidence.is_some()
                || self.freeze_authorization_evidence.is_some()
                || self.freeze_provenance.is_some()
                || self.obligation_set.is_some()
                || !self.obligations.is_empty()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.freeze_failure.is_some()
            && (self.scope_commitment.is_some()
                || self.freeze_admission_evidence.is_some()
                || self.freeze_authorization_evidence.is_some()
                || self.freeze_provenance.is_some()
                || self.obligation_set.is_some()
                || !self.obligations.is_empty()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if let Some(freeze) = self.freeze_provenance {
            let Some(scope) = self.scope_commitment.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(obligation_set) = self.obligation_set.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(admission) = self.freeze_admission_evidence.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let Some(authorization) = self.freeze_authorization_evidence.as_ref() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let freeze_matches_scope = freeze.scope_commitment() == scope.reference()
                && freeze.obligation_set() == obligation_set.reference()
                && freeze.host_evidence() == admission.reference();
            if !freeze_matches_scope {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            self.validate_freeze_admission_bindings(
                scope,
                obligation_set,
                admission,
                authorization,
            )?;
        } else if self.freeze_admission_evidence.is_some()
            || self.freeze_authorization_evidence.is_some()
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.scope_commitment.is_none()
            && (self.obligation_set.is_some()
                || !self.scope_extensions.is_empty()
                || !self.scope_extension_ledgers.is_empty())
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        self.validate_obligation_evidence()?;
        self.validate_scope_extension_evidence()?;
        // Attempt-scoped collection lengths are bounded by admission ordinals
        // and their per-attempt cardinality checks. Acknowledgement provenance
        // is append-only across attempts, so its lifetime bound is the encoded
        // coordinator-record limit rather than one attempt's obligation count.
        if self
            .administrative_resolutions
            .get(ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS)
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

    fn validate_freeze_admission_bindings(
        &self,
        scope: &ErasureScopeCommitmentV1,
        obligation_set: &ErasureObligationSetV1,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        let freeze = self
            .freeze_provenance
            .ok_or(ErasureErrorV1::ProvenanceMissing)?;
        if (
            admission.request(),
            admission.scope_commitment(),
            admission.obligation_set(),
            admission.freeze_position(),
            admission.policy(),
            admission.trust(),
            admission.authorization_provenance(),
            authorization.admission_body_digest(),
            authorization.policy(),
            authorization.trust(),
        ) != (
            scope.request(),
            scope.reference(),
            obligation_set.reference(),
            freeze.freeze_position(),
            obligation_set.policy(),
            obligation_set.trust(),
            authorization.reference(),
            admission.authorization_body_digest()?,
            obligation_set.policy(),
            obligation_set.trust(),
        ) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn validate_obligation_evidence(&self) -> Result<(), ErasureErrorV1> {
        let Some(set) = self.obligation_set.as_ref() else {
            return if self.obligations.is_empty() {
                Ok(())
            } else {
                Err(ErasureErrorV1::ProvenanceMissing)
            };
        };
        if !obligation_count_is_bounded(self.obligations.len()) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let references = self
            .obligations
            .iter()
            .map(ErasureObligationV1::reference)
            .collect::<Vec<_>>();
        if set.obligations() != references.as_slice() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let mut category_counts = [0_usize; ERASURE_INVENTORY_CATEGORY_COUNT];
        let mut command_owner_pairs = Vec::with_capacity(self.obligations.len());
        let mut category_target_pairs = Vec::with_capacity(self.obligations.len());
        for obligation in &self.obligations {
            if obligation.command_identity()
                != destruction_command_reference(set.request(), obligation.target())
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            let category = obligation.category().index();
            category_counts[category] = category_counts[category].saturating_add(1);
            command_owner_pairs.push((obligation.command_identity(), obligation.owner()));
            category_target_pairs.push((obligation.category(), obligation.target()));
        }
        command_owner_pairs.sort_unstable();
        category_target_pairs.sort_unstable();
        if category_counts
            .iter()
            .any(|count| !category_obligation_count_is_bounded(*count))
            || has_duplicate(&command_owner_pairs)
            || has_duplicate(&category_target_pairs)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(())
    }

    fn validate_scope_extension_evidence(&self) -> Result<(), ErasureErrorV1> {
        let Some(scope) = self.scope_commitment.as_ref() else {
            return Ok(());
        };
        let Some(lineage_rule) = scope.lineage_rule() else {
            return if self.scope_extensions.is_empty() && self.scope_extension_ledgers.is_empty() {
                Ok(())
            } else {
                Err(ErasureErrorV1::PolicyConflict)
            };
        };
        if !scope_extension_count_is_bounded(self.scope_extensions.len())
            || self.scope_extension_ledgers.len() != self.scope_extensions.len().saturating_add(1)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let mut forks = Vec::with_capacity(self.scope_extensions.len());
        let mut expected_predecessor = None;
        for extension in &self.scope_extensions {
            if (
                extension.request(),
                extension.scope_commitment(),
                extension.lineage_rule(),
                extension.predecessor_extension(),
            ) != (
                scope.request(),
                scope.reference(),
                lineage_rule,
                expected_predecessor,
            ) {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            expected_predecessor = Some(extension.reference());
            forks.push(extension.fork());
        }
        forks.sort_unstable();
        if has_duplicate(&forks) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let extension_references = self
            .scope_extensions
            .iter()
            .map(ErasureScopeExtensionV1::reference)
            .collect::<Vec<_>>();
        for (index, ledger) in self.scope_extension_ledgers.iter().enumerate() {
            let expected_extensions = &extension_references[..index];
            let expected_head = expected_extensions.last().copied();
            if ledger.scope_commitment() != scope.reference()
                || ledger.extensions() != expected_extensions
                || ledger.head() != expected_head
            {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        }
        Ok(())
    }

    fn effective_acknowledgement_provenance(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<(&ErasureObligationV1, &ErasureAcknowledgementProvenanceV1)> {
        ErasureEvidenceIndex::new(self).effective_provenance(admission)
    }

    fn effective_acknowledgements(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Vec<ErasureAcknowledgementV1> {
        let mut acknowledgements = self
            .effective_acknowledgement_provenance(admission)
            .into_iter()
            .map(|(obligation, provenance)| ErasureAcknowledgementV1 {
                obligation: obligation.reference(),
                target: obligation.target(),
                owner: obligation.owner(),
                evidence: provenance.evidence(),
                outcome: provenance.outcome(),
            })
            .collect::<Vec<_>>();
        acknowledgements.sort_unstable();
        acknowledgements
    }

    fn validate_attempt_chain(&self) -> Result<(), ErasureErrorV1> {
        let evidence = ErasureEvidenceIndex::new(self);
        let mut carried = BTreeMap::new();
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
            let acknowledgement_references =
                evidence.advance_effective_references(admission, &mut carried);
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
        let evidence = ErasureEvidenceIndex::new(self);
        let mut identities = Vec::with_capacity(self.acknowledgement_provenance.len());
        let scope = self
            .scope_commitment
            .as_ref()
            .map(ErasureScopeCommitmentV1::reference);
        for acknowledgement in &self.acknowledgement_provenance {
            let obligation = evidence
                .obligations
                .get(&acknowledgement.obligation())
                .copied()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let admission = evidence
                .admissions
                .get(&acknowledgement.attempt())
                .copied()
                .ok_or(ErasureErrorV1::ProvenanceMissing)?;
            let command_matches_obligation = evidence.admitted_commands.contains(&(
                acknowledgement.attempt(),
                acknowledgement.obligation(),
                acknowledgement.command(),
            ));
            let command_differs = obligation.command_identity() != acknowledgement.command();
            if admission.request() != acknowledgement.request()
                || !command_matches_obligation
                || command_differs
                || obligation.owner() != acknowledgement.owner()
                || Some(acknowledgement.scope()) != scope
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
        if !self
            .acknowledgement_provenance
            .iter()
            .map(acknowledgement_provenance_ordering_key)
            .is_sorted()
            || has_duplicate(&identities)
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
            .authorization_rejection
            .is_none_or(|record| record.request() == request)
            && self
                .scope_commitment
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_admission_evidence
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_provenance
                .is_none_or(|record| record.request() == request)
            && self
                .freeze_failure
                .is_none_or(|record| record.request() == request)
            && self
                .obligation_set
                .as_ref()
                .is_none_or(|record| record.request() == request)
            && self
                .scope_extensions
                .iter()
                .all(|record| record.request() == request)
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
                self.authorization_rejection.as_ref(),
                next.authorization_rejection.as_ref(),
            ),
            option_is_unchanged(
                self.scope_commitment.as_ref(),
                next.scope_commitment.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_admission_evidence.as_ref(),
                next.freeze_admission_evidence.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_authorization_evidence.as_ref(),
                next.freeze_authorization_evidence.as_ref(),
            ),
            option_is_unchanged(
                self.freeze_provenance.as_ref(),
                next.freeze_provenance.as_ref(),
            ),
            option_is_unchanged(self.freeze_failure.as_ref(), next.freeze_failure.as_ref()),
            next.obligations.starts_with(&self.obligations),
            option_is_unchanged(self.obligation_set.as_ref(), next.obligation_set.as_ref()),
            next.scope_extensions.starts_with(&self.scope_extensions),
            next.scope_extension_ledgers
                .starts_with(&self.scope_extension_ledgers),
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
    if input.unresolved_obligations.len() != input.command_identities.len() {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    if input
        .unresolved_obligations
        .get(ERASURE_MAX_OBLIGATIONS)
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
    if duplicate_obligation {
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

/// One deterministic destruction intent for an admitted obligation.
///
/// The command identifier is derived from `(request, target)` and may therefore
/// be shared by several category-scoped obligations. The obligation and owner
/// fields keep those durable intents distinct across retries and restarts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ErasureDestructionCommandV1 {
    /// Content address of the selected immutable obligation.
    pub obligation: ErasureReferenceV1,
    /// Category whose registered owner receives this intent.
    pub category: ErasureInventoryCategoryV1,
    /// The frozen artifact/key/replica target owned by this obligation.
    pub target: ErasureRequiredTargetV1,
    /// Independently authenticated category-scoped owner.
    pub owner: ErasureReferenceV1,
    /// Content-addressed command identity, stable across retries.
    pub command: ErasureReferenceV1,
    /// Host-authenticated attempt provenance.
    pub provenance: ErasureReferenceV1,
}

impl ErasureDestructionCommandV1 {
    /// Construct one owner-specific intent from a validated obligation.
    #[must_use]
    pub const fn from_obligation(
        obligation: &ErasureObligationV1,
        provenance: ErasureReferenceV1,
    ) -> Self {
        Self {
            obligation: obligation.reference(),
            category: obligation.category(),
            target: obligation.target(),
            owner: obligation.owner(),
            command: obligation.command_identity(),
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
    /// Every inventory category in canonical wire order.
    pub const CANONICAL: [Self; 4] = [Self::Artifact, Self::Key, Self::Replica, Self::Backup];

    const fn code(self) -> u64 {
        match self {
            Self::Artifact => 0,
            Self::Key => 1,
            Self::Replica => 2,
            Self::Backup => 3,
        }
    }
    const fn index(self) -> usize {
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

/// Construction fields for one frozen category/target/owner obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureObligationInputV1 {
    /// Policy-admitted category for this target.
    pub category: ErasureInventoryCategoryV1,
    /// Canonical target in the admitted freeze closure.
    pub target: ErasureRequiredTargetV1,
    /// Independently admitted category-scoped owner identity.
    pub owner: ErasureReferenceV1,
    /// Stable `(ERQ1, target)` destruction-command identity.
    pub command_identity: ErasureReferenceV1,
}

/// Immutable policy-selected obligation persisted at access freeze.
///
/// The canonical wire record is `ERO1 = [tag, version, category, target,
/// owner, command_identity]`. Its content address, rather than an inferred
/// `(category, target)` tuple, is the durable obligation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureObligationV1 {
    input: ErasureObligationInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureObligationV1 {
    /// Construct and content-address an immutable obligation.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureObligationInputV1) -> Result<Self, ErasureErrorV1> {
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the policy-selected category.
    #[must_use]
    pub const fn category(&self) -> ErasureInventoryCategoryV1 {
        self.input.category
    }

    /// Return the canonical frozen target.
    #[must_use]
    pub const fn target(&self) -> ErasureRequiredTargetV1 {
        self.input.target
    }

    /// Return the independently admitted category-scoped owner identity.
    #[must_use]
    pub const fn owner(&self) -> ErasureReferenceV1 {
        self.input.owner
    }

    /// Return the stable destruction-command identity.
    #[must_use]
    pub const fn command_identity(&self) -> ErasureReferenceV1 {
        self.input.command_identity
    }

    /// Return this obligation's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `ERO1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(&obligation_value(self), ERASURE_PORTABLE_RECORD_MAX_BYTES)
    }

    /// Decode and validate one exact `ERO1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_TARGETS,
        )
        .and_then(|value| exact_array(&value, 6).and_then(obligation_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(&obligation_value(&self), ERASURE_PORTABLE_RECORD_MAX_BYTES).map(|bytes| {
            Self {
                content_digest: ErasureReferenceV1::from_digest(domain_digest(
                    ERASURE_OBLIGATION_TAG_V1,
                    &bytes,
                )),
                ..self
            }
        })
    }
}

/// Construction fields for a frozen set of immutable obligations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureObligationSetInputV1 {
    /// ERQ1 whose policy admitted this exact set.
    pub request: ErasureReferenceV1,
    /// Strictly bytewise-increasing `ERO1` content addresses.
    pub obligations: Vec<ErasureReferenceV1>,
    /// Policy revision pinned by ERQ1.
    pub policy: ErasureReferenceV1,
    /// Trust revision admitted by the host at freeze.
    pub trust: ErasureReferenceV1,
}

/// Content-addressed frozen set of admitted obligations for an ERQ1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureObligationSetV1 {
    input: ErasureObligationSetInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureObligationSetV1 {
    /// Construct one exact `EROS1` record without normalizing its references.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for a duplicate, unordered, or oversized
    /// obligation collection. An empty set is valid when every applicability
    /// row is inapplicable.
    pub fn new(input: ErasureObligationSetInputV1) -> Result<Self, ErasureErrorV1> {
        if input.obligations.len() > ERASURE_MAX_OBLIGATIONS
            || !strictly_increasing(&input.obligations)
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

    /// Return the exact ordered obligation addresses.
    #[must_use]
    pub fn obligations(&self) -> &[ErasureReferenceV1] {
        &self.input.obligations
    }

    /// Return the ERQ1-pinned policy revision.
    #[must_use]
    pub const fn policy(&self) -> ErasureReferenceV1 {
        self.input.policy
    }

    /// Return the host-admitted trust revision.
    #[must_use]
    pub const fn trust(&self) -> ErasureReferenceV1 {
        self.input.trust
    }

    /// Return this obligation set's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode the exact `EROS1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error when serialization exceeds the V1 bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &obligation_set_value(self),
            ERASURE_OBLIGATION_SET_MAX_BYTES,
        )
    }

    /// Decode and validate one exact `EROS1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_OBLIGATION_SET_MAX_BYTES,
            ERASURE_MAX_OBLIGATIONS,
        )
        .and_then(|value| exact_array(&value, 6).and_then(obligation_set_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &obligation_set_value(&self),
            ERASURE_OBLIGATION_SET_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_OBLIGATION_SET_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for one append-only future-Fork scope extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionInputV1 {
    /// ERQ1 protected by the extension.
    pub request: ErasureReferenceV1,
    /// Initial immutable scope-commitment address.
    pub scope_commitment: ErasureReferenceV1,
    /// Canonical Timeline/Fork scope reference being appended.
    pub fork: ErasureReferenceV1,
    /// The non-null lineage rule pinned by the initial commitment.
    pub lineage_rule: ErasureReferenceV1,
    /// Immediately preceding extension address, if one exists.
    pub predecessor_extension: Option<ErasureReferenceV1>,
    /// Host-authenticated #186 future-Fork admission evidence.
    pub admission_provenance: ErasureReferenceV1,
}

/// Immutable future-Fork scope extension (`ERSE1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionV1 {
    input: ErasureScopeExtensionInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureScopeExtensionV1 {
    /// Construct and content-address one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when the record exceeds its bound.
    pub fn new(input: ErasureScopeExtensionInputV1) -> Result<Self, ErasureErrorV1> {
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

    /// Return the immutable initial scope-commitment address.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return the admitted future Timeline/Fork scope reference.
    #[must_use]
    pub const fn fork(&self) -> ErasureReferenceV1 {
        self.input.fork
    }

    /// Return the pinned lineage-expansion rule.
    #[must_use]
    pub const fn lineage_rule(&self) -> ErasureReferenceV1 {
        self.input.lineage_rule
    }

    /// Return the immediately preceding extension address, if any.
    #[must_use]
    pub const fn predecessor_extension(&self) -> Option<ErasureReferenceV1> {
        self.input.predecessor_extension
    }

    /// Return host-authenticated future-Fork admission evidence.
    #[must_use]
    pub const fn admission_provenance(&self) -> ErasureReferenceV1 {
        self.input.admission_provenance
    }

    /// Return this extension's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds its bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &scope_extension_value(self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
    }

    /// Decode and validate one exact `ERSE1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
            ERASURE_MAX_SCOPE_EXTENSIONS,
        )
        .and_then(|value| exact_array(&value, 8).and_then(scope_extension_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_extension_value(&self),
            ERASURE_PORTABLE_RECORD_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_SCOPE_EXTENSION_TAG_V1,
                &bytes,
            )),
            ..self
        })
    }
}

/// Construction fields for an immutable extension ledger snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionLedgerInputV1 {
    /// Initial immutable scope commitment.
    pub scope_commitment: ErasureReferenceV1,
    /// Extension addresses in oldest-to-newest predecessor order.
    pub extensions: Vec<ErasureReferenceV1>,
    /// The final extension address, or `None` for the empty ledger.
    pub head: Option<ErasureReferenceV1>,
}

/// Content-addressed immutable scope-extension ledger (`ERSEL1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureScopeExtensionLedgerV1 {
    input: ErasureScopeExtensionLedgerInputV1,
    content_digest: ErasureReferenceV1,
}

impl ErasureScopeExtensionLedgerV1 {
    /// Construct one exact ledger snapshot without normalizing its chain order.
    ///
    /// # Errors
    ///
    /// Returns a closed scope error for an oversized, duplicate, or
    /// head-inconsistent extension list.
    pub fn new(input: ErasureScopeExtensionLedgerInputV1) -> Result<Self, ErasureErrorV1> {
        let mut extension_identities = input.extensions.clone();
        extension_identities.sort_unstable();
        if input.extensions.len() > ERASURE_MAX_SCOPE_EXTENSIONS
            || has_duplicate(&extension_identities)
            || (input.extensions.is_empty() != input.head.is_none())
            || input
                .extensions
                .last()
                .is_some_and(|extension| Some(*extension) != input.head)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Self {
            input,
            content_digest: reference_zero(),
        }
        .with_digest()
    }

    /// Return the initial immutable scope commitment.
    #[must_use]
    pub const fn scope_commitment(&self) -> ErasureReferenceV1 {
        self.input.scope_commitment
    }

    /// Return extension addresses in oldest-to-newest predecessor order.
    #[must_use]
    pub fn extensions(&self) -> &[ErasureReferenceV1] {
        &self.input.extensions
    }

    /// Return the explicit durable head, if the ledger is non-empty.
    #[must_use]
    pub const fn head(&self) -> Option<ErasureReferenceV1> {
        self.input.head
    }

    /// Return this immutable ledger snapshot's content address.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.content_digest
    }

    /// Encode one exact `ERSEL1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error when serialization exceeds the V1 bound.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(
            &scope_extension_ledger_value(self),
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
        )
    }

    /// Decode and validate one exact `ERSEL1` record.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed, noncanonical, or oversized bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            bytes,
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
            ERASURE_MAX_SCOPE_EXTENSIONS,
        )
        .and_then(|value| exact_array(&value, 5).and_then(scope_extension_ledger_from_fields))
    }

    fn with_digest(self) -> Result<Self, ErasureErrorV1> {
        encode_limited(
            &scope_extension_ledger_value(&self),
            ERASURE_SCOPE_LEDGER_MAX_BYTES,
        )
        .map(|bytes| Self {
            content_digest: ErasureReferenceV1::from_digest(domain_digest(
                ERASURE_SCOPE_EXTENSION_LEDGER_TAG_V1,
                &bytes,
            )),
            ..self
        })
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
            self.target,
            self.obligation,
            self.owner,
            self.evidence,
            self.outcome.code(),
        )
            .cmp(&(
                other.target,
                other.obligation,
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
    /// Frozen closure: each target must be resolved exactly once.
    pub frozen_targets: Vec<ErasureRequiredTargetV1>,
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
            || input.frozen_targets.len() > ERASURE_MAX_INVENTORY_RESULTS
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
        input.frozen_targets.sort_unstable();
        input.pending_owners.sort_unstable();
        input.failed_owners.sort_unstable();
        if has_duplicate(&input.frozen_targets)
            || has_duplicate_acknowledgement_identity(&input.acknowledgements)
            || invalid_owner_sets(&input.pending_owners, &input.failed_owners)
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&input.frozen_targets, &input.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (derived_pending, derived_failed) =
            derived_inventory_outcome_owners(&input.inventories, &input.acknowledgements);
        if input.pending_owners != derived_pending || input.failed_owners != derived_failed {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !inventories_match_closure(&input.frozen_targets, &input.inventories) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // The caller's claim is descriptive input only.  ERC1 records the
        // weakest claim disclosed by the per-artifact transitions.
        input.replay_claim = weakest_inventory_claim(&input.inventories);
        let complete =
            acknowledgements_cover_inventory_entries(&input.inventories, &input.acknowledgements)
                && input
                    .acknowledgements
                    .iter()
                    .all(|ack| ack.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged);
        let unresolved =
            !complete || !input.pending_owners.is_empty() || !input.failed_owners.is_empty();
        if input.lifecycle == ErasureLifecycleV1::Complete && !complete {
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
    /// Return the frozen target closure.
    #[must_use]
    pub fn frozen_targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.0.frozen_targets
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

    /// Validate that this receipt closes the exact frozen obligation set.
    ///
    /// A standalone ERC1 decoder cannot know the policy-selected applicability
    /// matrix; the durable coordinator invokes this public check once it has
    /// recovered the frozen `ERO1` objects and `EROS1` set.
    ///
    /// # Errors
    ///
    /// Returns a closed error for missing, extraneous, or wrong-owner category
    /// evidence, or for a lifecycle inconsistent with the exact closure.
    pub fn validate_frozen_obligations(
        &self,
        obligations: &[ErasureObligationV1],
    ) -> Result<(), ErasureErrorV1> {
        if !inventories_match_frozen_obligations(&self.0.inventories, obligations) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let (pending, failed) =
            derived_outcome_owners_for_obligations(obligations, &self.0.acknowledgements);
        if self.0.pending_owners != pending || self.0.failed_owners != failed {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
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

fn derived_inventory_outcome_owners(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> (Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>) {
    let mut outcomes = BTreeMap::new();
    for acknowledgement in acknowledgements {
        let flags = outcomes
            .entry((acknowledgement.target, acknowledgement.owner))
            .or_insert((false, false));
        flags.0 = true;
        flags.1 |= acknowledgement.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged;
    }
    let mut pending = Vec::new();
    let mut failed = Vec::new();
    for entry in [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    {
        let (saw_acknowledgement, saw_non_positive) = outcomes
            .get(&(entry.target, entry.transition.owner))
            .copied()
            .unwrap_or((false, false));
        if !saw_acknowledgement {
            pending.push(entry.transition.owner);
        } else if saw_non_positive {
            failed.push(entry.transition.owner);
        }
    }
    pending.sort_unstable();
    pending.dedup();
    failed.sort_unstable();
    failed.dedup();
    pending.retain(|owner| failed.binary_search(owner).is_err());
    (pending, failed)
}

fn acknowledgements_cover_inventory_entries(
    inventories: &ErasureReceiptInventoriesV1,
    acknowledgements: &[ErasureAcknowledgementV1],
) -> bool {
    let mut inventory_pairs = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| (entry.target, entry.transition.owner))
    .collect::<Vec<_>>();
    let mut acknowledgement_pairs = acknowledgements
        .iter()
        .map(|acknowledgement| (acknowledgement.target, acknowledgement.owner))
        .collect::<Vec<_>>();
    inventory_pairs.sort_unstable();
    acknowledgement_pairs.sort_unstable();
    inventory_pairs == acknowledgement_pairs
}

fn inventories_match_frozen_obligations(
    inventories: &ErasureReceiptInventoriesV1,
    obligations: &[ErasureObligationV1],
) -> bool {
    let mut inventory_pairs = [
        &inventories.artifacts,
        &inventories.keys,
        &inventories.replicas,
        &inventories.backups,
    ]
    .into_iter()
    .flatten()
    .map(|entry| (entry.category, entry.target, entry.transition.owner))
    .collect::<Vec<_>>();
    let mut obligation_pairs = obligations
        .iter()
        .map(|obligation| {
            (
                obligation.category(),
                obligation.target(),
                obligation.owner(),
            )
        })
        .collect::<Vec<_>>();
    inventory_pairs.sort_unstable();
    obligation_pairs.sort_unstable();
    inventory_pairs == obligation_pairs
}

fn acknowledgements_close_frozen_obligations(
    acknowledgements: &[ErasureAcknowledgementV1],
    obligations: &[ErasureObligationV1],
) -> bool {
    let mut acknowledgement_closure = acknowledgements
        .iter()
        .map(|acknowledgement| {
            (
                acknowledgement.obligation,
                acknowledgement.target,
                acknowledgement.owner,
                acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged,
            )
        })
        .collect::<Vec<_>>();
    let mut obligation_closure = obligations
        .iter()
        .map(|obligation| {
            (
                obligation.reference(),
                obligation.target(),
                obligation.owner(),
                true,
            )
        })
        .collect::<Vec<_>>();
    acknowledgement_closure.sort_unstable();
    obligation_closure.sort_unstable();
    acknowledgement_closure == obligation_closure
}

fn derived_outcome_owners_for_obligations(
    obligations: &[ErasureObligationV1],
    acknowledgements: &[ErasureAcknowledgementV1],
) -> (Vec<ErasureReferenceV1>, Vec<ErasureReferenceV1>) {
    let acknowledged = acknowledgements
        .iter()
        .filter(|acknowledgement| {
            acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
        })
        .map(|acknowledgement| (acknowledgement.obligation, acknowledgement.owner))
        .collect::<BTreeSet<_>>();
    let mut pending = obligations
        .iter()
        .filter(|obligation| !acknowledged.contains(&(obligation.reference(), obligation.owner())))
        .map(ErasureObligationV1::owner)
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

/// Host-owned verifier for retained freeze-authorization evidence.
///
/// Persistence adapters require this capability before returning any
/// frozen-or-later coordinator record. This keeps ADR-060's authorization
/// rule inside the recovery interface instead of relying on caller discipline.
pub trait ErasureFreezeAuthorizationVerifierV1 {
    /// Verify one retained ERFA1 body and its ERFAA1 authorization evidence.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, policy, or trust error when the proof
    /// does not authenticate the supplied admission body.
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1>;
}

/// Coordinator record whose retained freeze authorization has been verified
/// for one persistence operation.
///
/// The inner record is intentionally private so persistence adapters cannot
/// construct a frozen commit without invoking the host-owned verifier. A
/// pre-freeze record also uses this capability and succeeds without evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedErasureCoordinatorRecordV1(ErasureCoordinatorRecordV1);

impl VerifiedErasureCoordinatorRecordV1 {
    /// Verify a record before it crosses the durable commit boundary.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or authorization error when retained freeze
    /// evidence is incomplete or rejected by the host-owned verifier.
    pub fn new(
        record: ErasureCoordinatorRecordV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Self, ErasureErrorV1> {
        record
            .verify_recovered_freeze_authorization(verifier)
            .map(|()| Self(record))
    }

    /// Borrow the verified record for adapter validation and encoding.
    #[must_use]
    pub const fn record(&self) -> &ErasureCoordinatorRecordV1 {
        &self.0
    }

    /// Consume the capability after a successful staged commit.
    #[must_use]
    pub fn into_record(self) -> ErasureCoordinatorRecordV1 {
        self.0
    }
}

/// Durable persistence SPI for the complete ERQ1/ERS1/ERC1 coordinator record.
///
/// This port contains persistence plus the mandatory recovery-verification
/// call supplied by the host. Authentication policy, target discovery,
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
    /// sufficient provenance. Frozen-or-later records must also pass the
    /// supplied host authorization verifier before they leave the adapter.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or encoding error when the record cannot be
    /// read or does not satisfy the V1 contract.
    fn load_record(
        &self,
        request: ErasureReferenceV1,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<Option<ErasureCoordinatorRecordV1>, ErasureErrorV1>;

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
        records: &[VerifiedErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1>;

    /// Persist one record through the batch transaction seam.
    ///
    /// Adapters normally implement only [`Self::commit_records`]; this wrapper
    /// keeps single-record operations on the same atomic validation path.
    ///
    /// # Errors
    ///
    /// Returns the adapter's closed storage, encoding, or conflict error.
    fn commit_record(
        &mut self,
        record: VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        self.commit_records(std::slice::from_ref(&record))
    }

    /// Atomically append a scope-extension ledger successor.
    ///
    /// The adapter compares the durable ledger reference before it makes the
    /// successor visible. It must accept an exact retry and reject a competing
    /// successor so the chain cannot branch.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or policy conflict error.
    fn compare_and_swap_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        expected_ledger: ErasureReferenceV1,
        record: VerifiedErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1>;

    /// Atomically append an administrative-resolution successor.
    ///
    /// The adapter compares the durable resolution head before it makes the
    /// successor visible. It must accept an exact retry and reject a competing
    /// successor so the recovery chain remains non-branching.
    ///
    /// # Errors
    ///
    /// Returns a closed storage or policy conflict error.
    fn compare_and_swap_administrative_resolution(
        &mut self,
        request: ErasureReferenceV1,
        expected_head: Option<ErasureReferenceV1>,
        record: VerifiedErasureCoordinatorRecordV1,
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

/// Application-facing erasure lifecycle interface.
///
/// This interface hides the concrete host-port type carried by
/// [`ErasureCoordinatorStateMachineV1`], so consumers depend on one stable
/// lifecycle seam rather than its persistence, policy, and irreversible-work
/// adapters. Those adapters vary independently in production and tests; this
/// interface is therefore the application seam, not a pass-through adapter.
/// Implementations must preserve the coordinator's validation and ordering
/// rules rather than forwarding directly to persistence.
pub trait ErasureCoordinator {
    /// Record an idempotent ERQ1 request.
    ///
    /// # Errors
    ///
    /// Returns a closed error if the request cannot be authenticated or stored.
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Submit a replacement ERQ1 after validating its rejected predecessor.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance, authorization, or storage error.
    fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
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
    /// Append one host-admitted future-Fork scope extension.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, scope, or CAS conflict error.
    fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
    /// Append one host-admitted administrative recovery resolution.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, provenance, or CAS conflict error.
    fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;
}

/// Host capability boundary for authentication, atomic freeze admission, and
/// irreversible-work admission.
pub trait ErasureCoordinatorPortV1:
    ErasurePersistencePortV1 + ErasureFreezeAuthorizationVerifierV1
{
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
    /// Authenticate a corrected submission against its rejected predecessor.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization or provenance error.
    fn admit_corrected_submission(
        &self,
        request: &ErasureRequestV1,
        correction: &ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1>;
    /// Atomically resolve scope, applicability obligations, and access freeze.
    ///
    /// An exact retry returns the same typed result. A rejection is itself a
    /// canonical failure object; it is never reconstructed from a generic
    /// operational error after the host has made its decision.
    ///
    /// # Errors
    ///
    /// Returns a closed operational error only when no admission decision was
    /// produced. Scope/freeze rejection is represented by the result value.
    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1>;
    /// Authenticate one future-Fork scope extension before its CAS append.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization or scope error.
    fn admit_scope_extension(
        &self,
        extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1>;
    /// Authenticate one administrative recovery resolution before its CAS append.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization or provenance error.
    fn admit_administrative_resolution(
        &self,
        resolution: &ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1>;
    /// Dispatch idempotent destruction commands for a frozen closure.
    ///
    /// The host must retain one durable intent per admitted obligation. Stable
    /// command identities may repeat when distinct category-scoped owners act
    /// on the same target; deduplication uses `(attempt, obligation)` rather
    /// than command identity alone. The core state machine never advances to
    /// `DestructionDispatched` unless this call succeeds.
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
    /// Admission is idempotent by the content-addressed admission reference.
    /// An exact retry after a coordinator commit failure must return the same
    /// successful decision; a conflicting admission for the active ordinal or
    /// receipt head must fail closed.
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
        acknowledgement: &ErasureAcknowledgementProvenanceV1,
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

/// Construction fields for one successful atomic access-freeze admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAtomicFreezeAdmissionInputV1 {
    /// Exact sorted target closure frozen by the host.
    pub targets: Vec<ErasureRequiredTargetV1>,
    /// Resolved scope input committed with the target closure.
    pub scope: ErasureScopeCommitmentInputV1,
    /// Exact category/target/owner obligations admitted by host policy.
    pub obligations: Vec<ErasureObligationV1>,
    /// Content-addressed set referencing `obligations`.
    pub obligation_set: ErasureObligationSetV1,
    /// Authoritative Tick Boundary position.
    pub freeze_position: u64,
    /// Complete canonical applicability and freeze-admission evidence.
    pub freeze_admission_evidence: ErasureFreezeAdmissionEvidenceV1,
    /// Retained #187-owned proof authenticating the admission body.
    pub freeze_authorization_evidence: ErasureFreezeAuthorizationEvidenceV1,
}

/// Typed successful result of the one atomic host freeze operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAtomicFreezeAdmissionV1 {
    input: ErasureAtomicFreezeAdmissionInputV1,
}

impl ErasureAtomicFreezeAdmissionV1 {
    /// Validate a host-produced atomic admission.
    ///
    /// # Errors
    ///
    /// Returns a closed scope or policy error if the exact commitments do not
    /// describe one internally consistent freeze.
    pub fn new(input: ErasureAtomicFreezeAdmissionInputV1) -> Result<Self, ErasureErrorV1> {
        if input.targets.is_empty()
            || !target_count_is_bounded(input.targets.len())
            || !strictly_increasing(&input.targets)
            || input.obligations.len() > ERASURE_MAX_OBLIGATIONS
            || input.scope.target_closure != target_closure_digest(&input.targets)
            || input.scope.request != input.obligation_set.request()
            || input.scope.target_closure == reference_zero()
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        ErasureScopeCommitmentV1::new(input.scope.clone())
            .and_then(|scope| Self::validate_commitments(input, &scope))
    }

    fn validate_commitments(
        input: ErasureAtomicFreezeAdmissionInputV1,
        scope: &ErasureScopeCommitmentV1,
    ) -> Result<Self, ErasureErrorV1> {
        let evidence = input.freeze_admission_evidence.clone();
        let authorization = input.freeze_authorization_evidence.clone();
        evidence
            .authorization_body_digest()
            .and_then(|body_digest| {
                if (
                    evidence.request(),
                    evidence.scope_commitment(),
                    evidence.obligation_set(),
                    evidence.freeze_position(),
                    evidence.policy(),
                    evidence.trust(),
                    evidence.authorization_provenance(),
                    authorization.admission_body_digest(),
                    authorization.policy(),
                    authorization.trust(),
                ) != (
                    input.scope.request,
                    scope.reference(),
                    input.obligation_set.reference(),
                    input.freeze_position,
                    input.obligation_set.policy(),
                    input.obligation_set.trust(),
                    authorization.reference(),
                    body_digest,
                    input.obligation_set.policy(),
                    input.obligation_set.trust(),
                ) {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
                let obligation_references = input
                    .obligations
                    .iter()
                    .map(ErasureObligationV1::reference)
                    .collect::<Vec<_>>();
                if input.obligation_set.obligations() != obligation_references.as_slice() {
                    return Err(ErasureErrorV1::ScopeInvalid);
                }
                let mut categories = [0_usize; ERASURE_INVENTORY_CATEGORY_COUNT];
                for obligation in &input.obligations {
                    if input.targets.binary_search(&obligation.target()).is_err()
                        || obligation.command_identity()
                            != destruction_command_reference(
                                input.scope.request,
                                obligation.target(),
                            )
                    {
                        return Err(ErasureErrorV1::ScopeInvalid);
                    }
                    let category = obligation.category().index();
                    categories[category] = categories[category].saturating_add(1);
                    if !category_obligation_count_is_bounded(categories[category]) {
                        return Err(ErasureErrorV1::ScopeInvalid);
                    }
                }
                let mut category_targets = input
                    .obligations
                    .iter()
                    .map(|obligation| (obligation.category(), obligation.target()))
                    .collect::<Vec<_>>();
                category_targets.sort_unstable();
                if category_targets.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(ErasureErrorV1::ScopeInvalid);
                }
                validate_applicability_obligations(
                    evidence.applicability_matrix(),
                    &input.targets,
                    &input.obligations,
                )
                .and_then(|()| {
                    let mut command_owners = input
                        .obligations
                        .iter()
                        .map(|obligation| (obligation.command_identity(), obligation.owner()))
                        .collect::<Vec<_>>();
                    command_owners.sort_unstable();
                    if command_owners.windows(2).any(|pair| pair[0] == pair[1]) {
                        Err(ErasureErrorV1::ScopeInvalid)
                    } else {
                        Ok(Self { input })
                    }
                })
            })
    }

    /// Return the frozen target closure.
    #[must_use]
    pub fn targets(&self) -> &[ErasureRequiredTargetV1] {
        &self.input.targets
    }

    /// Return the scope input persisted with this admission.
    #[must_use]
    pub const fn scope(&self) -> &ErasureScopeCommitmentInputV1 {
        &self.input.scope
    }

    /// Return category-scoped frozen obligations.
    #[must_use]
    pub fn obligations(&self) -> &[ErasureObligationV1] {
        &self.input.obligations
    }

    /// Return the frozen obligation-reference set.
    #[must_use]
    pub const fn obligation_set(&self) -> &ErasureObligationSetV1 {
        &self.input.obligation_set
    }

    /// Return the authoritative freeze position.
    #[must_use]
    pub const fn freeze_position(&self) -> u64 {
        self.input.freeze_position
    }

    /// Return complete canonical freeze-admission evidence.
    #[must_use]
    pub const fn freeze_admission_evidence(&self) -> &ErasureFreezeAdmissionEvidenceV1 {
        &self.input.freeze_admission_evidence
    }

    /// Return retained #187-owned authorization evidence.
    #[must_use]
    pub const fn freeze_authorization_evidence(&self) -> &ErasureFreezeAuthorizationEvidenceV1 {
        &self.input.freeze_authorization_evidence
    }
}

fn validate_applicability_obligations(
    matrix: &[ErasureFreezeApplicabilityRowV1],
    targets: &[ErasureRequiredTargetV1],
    obligations: &[ErasureObligationV1],
) -> Result<(), ErasureErrorV1> {
    if matrix.len()
        != targets
            .len()
            .saturating_mul(ERASURE_INVENTORY_CATEGORY_COUNT)
    {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let mut by_category_target = BTreeMap::new();
    for obligation in obligations {
        if by_category_target
            .insert((obligation.category(), obligation.target()), obligation)
            .is_some()
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
    }
    let mut applicable = 0_usize;
    for row in matrix {
        let Ok(target_index) = usize::try_from(row.target_index()) else {
            return Err(ErasureErrorV1::ScopeInvalid);
        };
        let Some(target) = targets.get(target_index) else {
            return Err(ErasureErrorV1::ScopeInvalid);
        };
        let obligation = by_category_target.get(&(row.category(), *target));
        match (row.decision(), row.owner(), obligation) {
            (ErasureApplicabilityDecisionV1::Inapplicable, None, None) => {}
            (ErasureApplicabilityDecisionV1::Applicable, Some(owner), Some(obligation))
                if obligation.owner() == owner =>
            {
                applicable = applicable.saturating_add(1);
            }
            _ => return Err(ErasureErrorV1::ScopeInvalid),
        }
    }
    if applicable == obligations.len() {
        Ok(())
    } else {
        Err(ErasureErrorV1::ScopeInvalid)
    }
}

/// Canonical result of the one atomic host freeze operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErasureAtomicFreezeResultV1 {
    /// The host froze one exact scope, target closure, and obligation matrix.
    Admitted(Box<ErasureAtomicFreezeAdmissionV1>),
    /// The host rejected freeze/scope work with durable canonical provenance.
    Rejected(ErasureFreezeFailureV1),
}

/// Public durable fields for reconstructing an ERQ1/ERS1/ERC1 coordinator record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureCoordinatorRecordPartsV1 {
    /// The exact authenticated request identity.
    pub request: ErasureRequestV1,
    /// The latest digest-linked ERS1 state.
    pub state: ErasureStateV1,
    /// The frozen required-target closure returned by the one atomic host
    /// admission. Each `(request, target)` tuple is the deterministic identity
    /// of one destruction command; no payload is persisted here.
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
    /// Host-authenticated dispatch provenance, if present.
    pub dispatch_provenance: Option<ErasureReferenceV1>,
    /// Durable reference to the current immutable scope-extension ledger.
    pub scope_extension_ledger: Option<ErasureReferenceV1>,
    /// Durable reference to the non-branching administrative-resolution head.
    pub administrative_resolution_head: Option<ErasureReferenceV1>,
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
    dispatch_provenance: Option<ErasureReferenceV1>,
    scope_extension_ledger: Option<ErasureReferenceV1>,
    administrative_resolution_head: Option<ErasureReferenceV1>,
    supporting_records: ErasureSupportingRecordsV1,
}

/// One independently bounded, content-addressed supporting-evidence object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasurePersistenceEvidenceV1 {
    reference: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
}

impl ErasurePersistenceEvidenceV1 {
    /// Return the content address used by persistence adapters.
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.reference
    }

    /// Return the canonical bytes for this independently bounded object.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

/// Normalized durable coordinator representation.
///
/// The bounded manifest contains ERQ1/ERS1 and references to supporting
/// evidence. Each evidence object is stored independently so the permitted
/// receipt history cannot be rejected by an unrelated aggregate byte limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasurePersistenceBundleV1 {
    manifest_cbor: Vec<u8>,
    evidence: Vec<ErasurePersistenceEvidenceV1>,
}

impl ErasurePersistenceBundleV1 {
    /// Return the bounded canonical coordinator manifest.
    #[must_use]
    pub fn manifest_cbor(&self) -> &[u8] {
        &self.manifest_cbor
    }

    /// Return independently bounded content-addressed evidence objects.
    #[must_use]
    pub fn evidence(&self) -> &[ErasurePersistenceEvidenceV1] {
        &self.evidence
    }
}

impl ErasureCoordinatorRecordV1 {
    /// Reconstruct a durable coordinator record from host storage.
    ///
    /// Hosts may persist the returned public fields in any representation and
    /// must validate the complete record again when rehydrating it.  This
    /// constructor is the only supported boundary for records loaded by an
    /// [`ErasurePersistencePortV1`].
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
            scope_extension_ledger: parts.scope_extension_ledger,
            administrative_resolution_head: parts.administrative_resolution_head,
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
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| exact_array(&value, 13).and_then(record_from_fields))
    }

    /// Split this record into a bounded manifest and independently bounded
    /// content-addressed supporting objects for durable adapters.
    ///
    /// # Errors
    ///
    /// Returns a closed validation or encoding error for invalid evidence.
    pub fn to_persistence_bundle(&self) -> Result<ErasurePersistenceBundleV1, ErasureErrorV1> {
        self.validate(self.state.coordinator()).and_then(|()| {
            let manifest_cbor = encode_limited(
                &persistence_manifest_value(self),
                ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            )?;
            let mut evidence = BTreeMap::new();
            self.supporting_records
                .persistence_evidence()?
                .into_iter()
                .try_for_each(|(reference, canonical_cbor)| {
                    match evidence.entry(reference) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(canonical_cbor);
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => {
                            if entry.get() != &canonical_cbor {
                                return Err(ErasureErrorV1::ProvenanceMissing);
                            }
                        }
                    }
                    Ok(())
                })?;
            Ok(ErasurePersistenceBundleV1 {
                manifest_cbor,
                evidence: evidence
                    .into_iter()
                    .map(|(reference, canonical_cbor)| ErasurePersistenceEvidenceV1 {
                        reference,
                        canonical_cbor,
                    })
                    .collect(),
            })
        })
    }

    /// Rehydrate a normalized durable record through a content-addressed
    /// evidence resolver.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding or provenance error when the manifest is
    /// malformed, an object is unavailable, or bytes do not match their
    /// expected content address.
    pub fn from_persistence_manifest(
        manifest_cbor: &[u8],
        evidence: &mut dyn FnMut(ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1>,
    ) -> Result<Self, ErasureErrorV1> {
        decode_limited(
            manifest_cbor,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
            ERASURE_COORDINATOR_RECORD_MAX_BYTES,
        )
        .and_then(|value| {
            exact_array(&value, 13)
                .and_then(|fields| record_from_persistence_manifest(fields, evidence))
        })
    }

    /// Verify retained host authorization before a recovered record is returned.
    ///
    /// Pre-freeze records carry neither ERFA1 nor ERFAA1 evidence. Every
    /// frozen-or-later record carries both and must pass the supplied host
    /// verifier; a partial pair fails closed.
    ///
    /// # Errors
    ///
    /// Returns a closed provenance or host-verification error.
    pub fn verify_recovered_freeze_authorization(
        &self,
        verifier: &dyn ErasureFreezeAuthorizationVerifierV1,
    ) -> Result<(), ErasureErrorV1> {
        match (
            self.supporting_records.freeze_admission_evidence(),
            self.supporting_records.freeze_authorization_evidence(),
        ) {
            (Some(admission), Some(authorization)) => {
                verifier.validate_freeze_authorization(admission, authorization)
            }
            (None, None) => Ok(()),
            _ => Err(ErasureErrorV1::ProvenanceMissing),
        }
    }

    fn retain_authorization_rejection(
        &mut self,
        state: ErasureStateV1,
        rejection: ErasureAuthorizationRejectionV1,
    ) {
        self.state = state;
        self.supporting_records.authorization_rejection = Some(rejection);
    }

    fn retain_atomic_freeze(
        &mut self,
        state: ErasureStateV1,
        admission: &ErasureAtomicFreezeAdmissionV1,
        scope: ErasureScopeCommitmentV1,
        freeze: ErasureFreezeProvenanceV1,
        ledger: Option<ErasureScopeExtensionLedgerV1>,
    ) {
        self.state = state;
        self.targets = admission.targets().to_vec();
        self.freeze_provenance = Some(freeze.reference());
        self.scope_extension_ledger = ledger
            .as_ref()
            .map(ErasureScopeExtensionLedgerV1::reference);
        self.supporting_records.scope_commitment = Some(scope);
        self.supporting_records.freeze_admission_evidence =
            Some(admission.freeze_admission_evidence().clone());
        self.supporting_records.freeze_authorization_evidence =
            Some(admission.freeze_authorization_evidence().clone());
        self.supporting_records.freeze_provenance = Some(freeze);
        self.supporting_records.obligations = admission.obligations().to_vec();
        self.supporting_records.obligation_set = Some(admission.obligation_set().clone());
        self.supporting_records.scope_extension_ledgers = ledger.into_iter().collect();
    }

    fn retain_freeze_failure(&mut self, state: ErasureStateV1, failure: ErasureFreezeFailureV1) {
        self.state = state;
        self.supporting_records.freeze_failure = Some(failure);
    }

    fn retain_acknowledgement(
        &mut self,
        admission: &ErasureRetryAdmissionV1,
        provenance: &ErasureAcknowledgementProvenanceV1,
    ) {
        self.supporting_records
            .acknowledgement_provenance
            .push(*provenance);
        self.supporting_records
            .acknowledgement_provenance
            .sort_unstable_by_key(acknowledgement_provenance_ordering_key);
        self.acknowledgements = self
            .supporting_records
            .effective_acknowledgements(admission);
    }

    fn retain_terminal_receipt(
        &mut self,
        input: ErasureReceiptInputV1,
        outcome: &ErasureAttemptOutcomeV1,
        receipt: ErasureReceiptV1,
        provenance: &ErasureReceiptProvenanceV1,
    ) {
        self.receipt_input = Some(input);
        self.receipt = Some(receipt.clone());
        self.supporting_records.attempt_outcomes.push(*outcome);
        self.supporting_records.receipts.push(receipt);
        self.supporting_records.receipt_provenance.push(*provenance);
    }

    fn retain_scope_extension(
        &mut self,
        extension: ErasureScopeExtensionV1,
        successor: ErasureScopeExtensionLedgerV1,
    ) {
        self.scope_extension_ledger = Some(successor.reference());
        self.supporting_records.scope_extensions.push(extension);
        self.supporting_records
            .scope_extension_ledgers
            .push(successor);
    }

    fn retain_administrative_resolution(&mut self, resolution: ErasureAdministrativeResolutionV1) {
        self.administrative_resolution_head = Some(resolution.reference());
        self.supporting_records
            .administrative_resolutions
            .push(resolution);
    }

    /// Validate a replacement against the currently persisted record.
    ///
    /// Same-byte retries are idempotent. The only same-state extensions are
    /// admitted acknowledgement evidence, scope-ledger successors, and
    /// administrative-resolution successors; all lifecycle changes require a
    /// new ERS1 predecessor link.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::PolicyConflict`] when the replacement is not
    /// a permitted monotonic update.
    pub fn validate_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        let coordinator = self.state.coordinator();
        self.validate(coordinator)
            .and_then(|()| next.validate(coordinator))
            .and_then(|()| self.validate_replacement_fields(next))
    }

    fn validate_replacement_fields(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        if self.request != next.request {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if !self
            .supporting_records
            .is_prefix_of(&next.supporting_records)
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
        if (
            &self.request,
            &self.targets,
            &self.receipt,
            &self.receipt_input,
            self.authorize_provenance,
            self.freeze_provenance,
        ) != (
            &next.request,
            &next.targets,
            &next.receipt,
            &next.receipt_input,
            next.authorize_provenance,
            next.freeze_provenance,
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let lifecycle = self.state.lifecycle();
        let frozen = matches!(
            lifecycle,
            ErasureLifecycleV1::AccessFrozen
                | ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
                | ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
        );
        if self.dispatch_provenance != next.dispatch_provenance
            && !matches!(
                (
                    lifecycle,
                    self.dispatch_provenance,
                    next.dispatch_provenance
                ),
                (ErasureLifecycleV1::AccessFrozen, None, Some(_))
            )
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if (self.scope_extension_ledger != next.scope_extension_ledger
            || self.administrative_resolution_head != next.administrative_resolution_head)
            && !frozen
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if self.acknowledgements != next.acknowledgements
            && !matches!(
                lifecycle,
                ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
            )
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        Ok(())
    }

    fn validate_advanced_replacement(&self, next: &Self) -> Result<(), ErasureErrorV1> {
        if next.state.validate_predecessor(&self.state).is_err() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let targets_continue = next.targets == self.targets
            || (self.state.lifecycle() == ErasureLifecycleV1::Authorized
                && next.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
                && !next.targets.is_empty());
        if !targets_continue {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let initializes_scope_extension_ledger = self.state.lifecycle()
            == ErasureLifecycleV1::Authorized
            && next.state.lifecycle() == ErasureLifecycleV1::AccessFrozen
            && self.scope_extension_ledger.is_none()
            && next.scope_extension_ledger.is_some();
        if (next.scope_extension_ledger != self.scope_extension_ledger
            && !initializes_scope_extension_ledger)
            || next.administrative_resolution_head != self.administrative_resolution_head
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if ![
            (self.authorize_provenance, next.authorize_provenance),
            (self.freeze_provenance, next.freeze_provenance),
            (self.dispatch_provenance, next.dispatch_provenance),
        ]
        .into_iter()
        .all(|(current, replacement)| current.is_none() || current == replacement)
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

    /// Return the immutable scope-extension ledger reference, when future-Fork
    /// semantics were admitted at freeze.
    #[must_use]
    pub const fn scope_extension_ledger(&self) -> Option<ErasureReferenceV1> {
        self.scope_extension_ledger
    }

    /// Return the durable administrative-resolution chain head, if present.
    #[must_use]
    pub const fn administrative_resolution_head(&self) -> Option<ErasureReferenceV1> {
        self.administrative_resolution_head
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
        self.supporting_records
            .correction_provenance()
            .ok_or(ErasureErrorV1::ProvenanceMissing)
            .and_then(|correction| {
                let predecessor_matches = (
                    predecessor.request.reference(),
                    predecessor.state.lifecycle(),
                    predecessor.state.state_digest(),
                ) == (
                    correction.rejected_request(),
                    ErasureLifecycleV1::Rejected,
                    correction.rejected_terminal_state(),
                );
                predecessor_matches
                    .then_some(())
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
            .and_then(|()| predecessor.validate(predecessor.state.coordinator()))
            .and_then(|()| {
                let rejection_matches = predecessor
                    .supporting_records
                    .freeze_failure()
                    .is_some_and(|failure| failure.reference() == predecessor.state.provenance())
                    || predecessor
                        .supporting_records
                        .authorization_rejection()
                        .is_some_and(|rejection| {
                            rejection.reference() == predecessor.state.provenance()
                        });
                rejection_matches
                    .then_some(())
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
    }

    fn validate_scope(&self) -> Result<(), ErasureErrorV1> {
        if !target_count_is_bounded(self.targets.len()) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !strictly_increasing(&self.targets) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if has_duplicate_acknowledgement_identity(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !strictly_increasing(&self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        if !acknowledgements_are_closure_subset(&self.targets, &self.acknowledgements) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let obligation_identities = self
            .supporting_records
            .obligations()
            .iter()
            .map(|obligation| {
                (
                    obligation.reference(),
                    obligation.target(),
                    obligation.owner(),
                )
            })
            .collect::<BTreeSet<_>>();
        if !self.acknowledgements.iter().all(|acknowledgement| {
            obligation_identities.contains(&(
                acknowledgement.obligation,
                acknowledgement.target,
                acknowledgement.owner,
            ))
        }) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if let Some(admission) = self.supporting_records.retry_admissions().last() {
            let expected = self
                .supporting_records
                .effective_acknowledgements(admission);
            if expected.as_slice() != self.acknowledgements.as_slice() {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
        } else if !self.acknowledgements.is_empty() {
            return Err(ErasureErrorV1::ProvenanceMissing);
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
        ) && (!self.targets.is_empty()
            || !self.acknowledgements.is_empty()
            || self.receipt.is_some()
            || self.receipt_input.is_some()
            || self.scope_extension_ledger.is_some()
            || self.administrative_resolution_head.is_some())
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        if lifecycle == ErasureLifecycleV1::Authorized
            && (!self.targets.is_empty()
                || !self.acknowledgements.is_empty()
                || self.receipt.is_some()
                || self.receipt_input.is_some()
                || self.scope_extension_ledger.is_some()
                || self.administrative_resolution_head.is_some())
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
        Ok(())
    }

    fn validate_frozen_evidence(
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
            let (Some(scope), Some(freeze), Some(obligation_set), Some(admission)) = (
                self.supporting_records.scope_commitment(),
                self.supporting_records.freeze_provenance(),
                self.supporting_records.obligation_set(),
                self.supporting_records.freeze_admission_evidence(),
            ) else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            let expected_state_provenance =
                (lifecycle == ErasureLifecycleV1::AccessFrozen).then_some(freeze.reference());
            let actual_state_provenance =
                (lifecycle == ErasureLifecycleV1::AccessFrozen).then_some(self.state.provenance());
            if (
                scope.target_closure(),
                obligation_set.request(),
                obligation_set.policy(),
                freeze.request(),
                freeze.scope_commitment(),
                freeze.obligation_set(),
                freeze.host_evidence(),
                self.freeze_provenance,
                self.state.freeze_position(),
                freeze.freeze_position(),
                actual_state_provenance,
            ) != (
                target_closure_digest(&self.targets),
                self.request.reference(),
                self.request.policy(),
                self.request.reference(),
                scope.reference(),
                obligation_set.reference(),
                admission.reference(),
                Some(freeze.reference()),
                Some(freeze.freeze_position()),
                freeze.freeze_position(),
                expected_state_provenance,
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            for obligation in self.supporting_records.obligations() {
                if self.targets.binary_search(&obligation.target()).is_err()
                    || obligation.command_identity()
                        != destruction_command_reference(
                            self.request.reference(),
                            obligation.target(),
                        )
                {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            return validate_applicability_obligations(
                admission.applicability_matrix(),
                &self.targets,
                self.supporting_records.obligations(),
            )
            .and_then(|()| {
                let expected_ledger = scope.lineage_rule().and_then(|_| {
                    self.supporting_records
                        .scope_extension_ledgers()
                        .last()
                        .map(ErasureScopeExtensionLedgerV1::reference)
                });
                if self.scope_extension_ledger == expected_ledger {
                    Ok(())
                } else {
                    Err(ErasureErrorV1::ProvenanceMissing)
                }
            });
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
        let rejected_before_authorization = lifecycle == ErasureLifecycleV1::Rejected
            && self.supporting_records.authorization_rejection().is_some();
        if (!rejected_before_authorization && actual != expected)
            || (rejected_before_authorization && actual != (false, false, false))
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        Ok(())
    }

    fn validate_administrative_resolution_head(&self) -> Result<(), ErasureErrorV1> {
        let resolutions = self.supporting_records.administrative_resolutions();
        let expected_head = resolutions
            .last()
            .map(ErasureAdministrativeResolutionV1::reference);
        if self.administrative_resolution_head != expected_head {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if resolutions.is_empty() {
            return Ok(());
        }
        let (Some(scope), Some(obligation_set)) = (
            self.supporting_records.scope_commitment(),
            self.supporting_records.obligation_set(),
        ) else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        if resolutions.iter().any(|resolution| {
            (
                resolution.request(),
                resolution.scope_commitment(),
                resolution.policy(),
                resolution.trust(),
            ) != (
                self.request.reference(),
                scope.reference(),
                self.request.policy(),
                obligation_set.trust(),
            )
        }) {
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
        let (Some(receipt), Some(receipt_input)) =
            (self.receipt.as_ref(), self.receipt_input.as_ref())
        else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        let mut acknowledgements = self.acknowledgements.clone();
        acknowledgements.sort_unstable();
        ErasureReceiptV1::new(receipt_input.clone())
            .and_then(|reconstructed| {
                if (
                    receipt,
                    receipt.terminal_state(),
                    receipt.lifecycle(),
                    receipt.coordinator(),
                    receipt.replay_claim(),
                    receipt.0.request,
                    receipt.frozen_targets(),
                ) != (
                    &reconstructed,
                    self.state.state_digest(),
                    lifecycle,
                    coordinator,
                    self.state.replay_claim(),
                    self.request.reference(),
                    self.targets.as_slice(),
                ) {
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
                receipt.validate_frozen_obligations(self.supporting_records.obligations())
            })
            .and_then(|()| {
                let (pending, failed) = derived_outcome_owners_for_obligations(
                    self.supporting_records.obligations(),
                    receipt.acknowledgements(),
                );
                if (self.state.pending_owners(), self.state.failed_owners())
                    != (pending.as_slice(), failed.as_slice())
                {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
                let (Some(outcome), Some(provenance)) = (
                    self.supporting_records.attempt_outcomes().last(),
                    self.supporting_records.receipt_provenance().last(),
                ) else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                };
                if (
                    self.state.provenance(),
                    receipt.provenance(),
                    provenance.terminal_state(),
                ) != (
                    outcome.reference(),
                    provenance.reference(),
                    self.state.state_digest(),
                ) {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
                Ok(())
            })
    }

    fn validate(&self, coordinator: ErasureReferenceV1) -> Result<(), ErasureErrorV1> {
        if (self.request.reference(), self.state.coordinator())
            != (self.state.request(), coordinator)
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        let lifecycle = self.state.lifecycle();
        self.supporting_records
            .validate()
            .and_then(|()| {
                self.supporting_records
                    .validates_request(self.request.reference())
            })
            .and_then(|()| {
                if self
                    .supporting_records
                    .correction_provenance()
                    .is_some_and(|correction| self.request.provenance() != correction.reference())
                {
                    Err(ErasureErrorV1::ProvenanceMissing)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| self.validate_supporting_lifecycle(lifecycle))
            .and_then(|()| self.validate_scope())
            .and_then(|()| self.validate_lifecycle_shape(lifecycle))
            .and_then(|()| self.validate_frozen_evidence(lifecycle))
            .and_then(|()| self.validate_provenance(lifecycle))
            .and_then(|()| self.validate_administrative_resolution_head())
            .and_then(|()| self.validate_terminal(lifecycle, coordinator))
    }

    fn validate_supporting_lifecycle(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        self.validate_supporting_evidence_shape(lifecycle)
            .and_then(|()| self.validate_attempt_evidence_shape(lifecycle))
            .and_then(|()| {
                if matches!(
                    lifecycle,
                    ErasureLifecycleV1::Complete | ErasureLifecycleV1::PartialFailure
                ) && self.supporting_records.receipts().last() != self.receipt.as_ref()
                {
                    Err(ErasureErrorV1::ProvenanceMissing)
                } else {
                    Ok(())
                }
            })
    }

    fn validate_supporting_evidence_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        let scope = self.supporting_records.scope_commitment();
        let admission = self.supporting_records.freeze_admission_evidence();
        let freeze_authorization = self.supporting_records.freeze_authorization_evidence();
        let freeze = self.supporting_records.freeze_provenance();
        let failure = self.supporting_records.freeze_failure();
        let authorization_rejection = self.supporting_records.authorization_rejection();
        let obligation_set = self.supporting_records.obligation_set();
        match lifecycle {
            ErasureLifecycleV1::Submitted | ErasureLifecycleV1::Authorized => {
                if (
                    scope.is_some(),
                    admission.is_some(),
                    freeze_authorization.is_some(),
                    freeze.is_some(),
                    failure.is_some(),
                    authorization_rejection.is_some(),
                    obligation_set.is_some(),
                ) != (false, false, false, false, false, false, false)
                {
                    return Err(ErasureErrorV1::PolicyConflict);
                }
            }
            ErasureLifecycleV1::Rejected => {
                if let Some(failure) = failure {
                    let Some(authorization) = self.authorize_provenance else {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    };
                    if (
                        scope.is_some(),
                        admission.is_some(),
                        freeze_authorization.is_some(),
                        freeze.is_some(),
                        failure.authorization_provenance(),
                        self.state.provenance(),
                    ) != (
                        false,
                        false,
                        false,
                        false,
                        authorization,
                        failure.reference(),
                    ) || authorization_rejection.is_some()
                        || obligation_set.is_some()
                    {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                } else if let Some(rejection) = authorization_rejection {
                    if (
                        scope.is_some(),
                        admission.is_some(),
                        freeze_authorization.is_some(),
                        freeze.is_some(),
                        obligation_set.is_some(),
                        self.authorize_provenance,
                        rejection.request(),
                        self.state.provenance(),
                    ) != (
                        false,
                        false,
                        false,
                        false,
                        false,
                        None,
                        self.request.reference(),
                        rejection.reference(),
                    ) {
                        return Err(ErasureErrorV1::ProvenanceMissing);
                    }
                } else {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
            ErasureLifecycleV1::AccessFrozen
            | ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements
            | ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure => {
                if (
                    scope.is_some(),
                    admission.is_some(),
                    freeze_authorization.is_some(),
                    freeze.is_some(),
                    failure.is_some(),
                    authorization_rejection.is_some(),
                    obligation_set.is_some(),
                ) != (true, true, true, true, false, false, true)
                {
                    return Err(ErasureErrorV1::ProvenanceMissing);
                }
            }
        }
        Ok(())
    }

    fn validate_attempt_evidence_shape(
        &self,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(), ErasureErrorV1> {
        let has_attempt_evidence = !self.supporting_records.retry_admissions().is_empty();
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
            {
                return Err(ErasureErrorV1::PolicyConflict);
            }
        }
        if matches!(
            lifecycle,
            ErasureLifecycleV1::DestructionDispatched
                | ErasureLifecycleV1::AwaitingAcknowledgements
        ) {
            let Some(admission) = self.supporting_records.retry_admissions().last() else {
                return Err(ErasureErrorV1::ProvenanceMissing);
            };
            if self.state.provenance() != admission.reference()
                || self.dispatch_provenance != Some(admission.reference())
            {
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
        match self.port.load_record(request, &self.port) {
            Ok(Some(record)) => self.validate_recovered_record(&record).map(|()| {
                self.cache(record.clone());
                record
            }),
            Ok(None) => Err(ErasureErrorV1::ProvenanceMissing),
            Err(error) => Err(error),
        }
    }

    fn validate_recovered_record(
        &self,
        record: &ErasureCoordinatorRecordV1,
    ) -> Result<(), ErasureErrorV1> {
        record
            .validate(self.coordinator)
            .and_then(|()| verify_predecessor_chain(record.state.clone(), &self.port))
    }
    fn commit(&mut self, record: ErasureCoordinatorRecordV1) -> Result<(), ErasureErrorV1> {
        record.validate(self.coordinator).and_then(|()| {
            VerifiedErasureCoordinatorRecordV1::new(record.clone(), &self.port)
                .and_then(|verified| self.port.commit_record(verified))
                .map(|()| self.cache(record))
        })
    }
    fn commit_records(
        &mut self,
        records: &[ErasureCoordinatorRecordV1],
    ) -> Result<(), ErasureErrorV1> {
        records
            .iter()
            .try_for_each(|record| record.validate(self.coordinator))
            .and_then(|()| {
                records
                    .iter()
                    .cloned()
                    .map(|record| VerifiedErasureCoordinatorRecordV1::new(record, &self.port))
                    .collect::<Result<Vec<_>, _>>()
            })
            .and_then(|verified| self.port.commit_records(&verified))
            .map(|()| {
                records
                    .iter()
                    .cloned()
                    .for_each(|record| self.cache(record));
            })
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
        match self.port.load_record(request.reference(), &self.port) {
            Ok(Some(record)) => self.validate_recovered_record(&record).and_then(|()| {
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
                            scope_extension_ledger: None,
                            administrative_resolution_head: None,
                            supporting_records: ErasureSupportingRecordsV1::default(),
                        };
                        self.commit(record).map(|()| state)
                    })
            }),
            Err(error) => Err(error),
        }
    }

    /// Submit a replacement request after host-authenticating its rejected
    /// predecessor and correction provenance.
    ///
    /// # Errors
    ///
    /// Returns a closed authentication, predecessor, or durable-record error.
    pub fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if request.provenance() != correction.reference() {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        match self.port.load_record(request.reference(), &self.port) {
            Ok(Some(record)) => self
                .validate_recovered_record(&record)
                .and_then(|()| {
                    if record.request != request
                        || record.supporting_records.correction_provenance() != Some(&correction)
                    {
                        Err(ErasureErrorV1::PolicyConflict)
                    } else {
                        Ok(())
                    }
                })
                .map(|()| {
                    let state = record.state.clone();
                    self.cache(record);
                    state
                }),
            Ok(None) => self
                .port
                .load_record(correction.rejected_request(), &self.port)
                .and_then(|predecessor| predecessor.ok_or(ErasureErrorV1::ProvenanceMissing))
                .and_then(|predecessor| {
                    predecessor
                        .validate(self.coordinator)
                        .and_then(|()| {
                            verify_predecessor_chain(predecessor.state.clone(), &self.port)
                        })
                        .and_then(|()| self.port.authenticate(&request))
                        .and_then(|()| self.port.admit_corrected_submission(&request, &correction))
                        .and_then(|()| {
                            ErasureStateV1::submitted(
                                request.reference(),
                                self.coordinator,
                                request.provenance(),
                            )
                        })
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
                                scope_extension_ledger: None,
                                administrative_resolution_head: None,
                                supporting_records: ErasureSupportingRecordsV1 {
                                    correction_provenance: Some(correction),
                                    ..ErasureSupportingRecordsV1::default()
                                },
                            };
                            record
                                .validate_correction_predecessor(&predecessor)
                                .and_then(|()| self.commit(record))
                                .map(|()| state)
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
            let replay_claim = record.state.replay_claim();
            self.port
                .admit_authorization(
                    request,
                    provenance,
                    ErasureAuthorizationDecisionV1::Authorized,
                )
                .and_then(|()| {
                    record.state.transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::Authorized,
                        freeze_position: None,
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim,
                        provenance,
                    })
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
                return record
                    .supporting_records
                    .authorization_rejection()
                    .filter(|rejection| rejection.authorization_provenance() == provenance)
                    .map_or(Err(ErasureErrorV1::PolicyConflict), |_| Ok(record.state));
            }
            let replay_claim = record.state.replay_claim();
            self.port
                .admit_authorization(
                    request,
                    provenance,
                    ErasureAuthorizationDecisionV1::Rejected,
                )
                .and_then(|()| {
                    ErasureAuthorizationRejectionV1::new(ErasureAuthorizationRejectionInputV1 {
                        request,
                        authorization_provenance: provenance,
                    })
                })
                .and_then(|rejection| {
                    record
                        .state
                        .transition(ErasureStateTransitionV1 {
                            lifecycle: ErasureLifecycleV1::Rejected,
                            freeze_position: None,
                            pending_owners: Vec::new(),
                            failed_owners: Vec::new(),
                            acknowledged_targets: Vec::new(),
                            replay_claim,
                            provenance: rejection.reference(),
                        })
                        .map(|state| (rejection, state))
                })
                .and_then(|(rejection, state)| {
                    record.retain_authorization_rejection(state, rejection);
                    let state = record.state.clone();
                    self.commit(record).map(|()| state)
                })
        })
    }
    /// Persist the one host-produced atomic access-freeze decision.
    ///
    /// Exact retries return the durable state, including a canonical rejected
    /// state when the host rejected scope or freeze work.
    ///
    /// # Errors
    ///
    /// Returns a closed lifecycle, host, or durable-record error.
    pub fn freeze_inventory(
        &mut self,
        request: ErasureReferenceV1,
        transition: ErasureStateTransitionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners,
            failed_owners,
            acknowledged_targets,
            replay_claim,
            provenance,
        } = transition;
        let transition = ErasureStateTransitionV1 {
            lifecycle,
            freeze_position,
            pending_owners,
            failed_owners,
            acknowledged_targets,
            replay_claim,
            provenance,
        };
        self.record(request).and_then(|mut record| {
            if record.state.lifecycle() == ErasureLifecycleV1::Rejected
                && record.supporting_records.freeze_failure().is_some()
            {
                return Ok(record.state);
            }
            if record.freeze_provenance.is_some() {
                return (transition.lifecycle == ErasureLifecycleV1::AccessFrozen)
                    .then_some(record.state)
                    .ok_or(ErasureErrorV1::PolicyConflict);
            }
            if !matches!(
                (record.state.lifecycle(), transition.lifecycle),
                (
                    ErasureLifecycleV1::Authorized,
                    ErasureLifecycleV1::AccessFrozen
                )
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            self.port
                .admit_atomic_freeze(request, &transition)
                .and_then(|result| match result {
                    ErasureAtomicFreezeResultV1::Rejected(failure) => {
                        self.persist_freeze_rejection(&mut record, failure)
                    }
                    ErasureAtomicFreezeResultV1::Admitted(admission) => {
                        self.persist_atomic_freeze(&mut record, &admission)
                    }
                })
        })
    }

    fn persist_atomic_freeze(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        admission: &ErasureAtomicFreezeAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let request = record.request.reference();
        if admission.scope().request != request
            || admission.obligation_set().request() != request
            || admission.obligation_set().policy() != record.request.policy()
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        self.port
            .validate_freeze_authorization(
                admission.freeze_admission_evidence(),
                admission.freeze_authorization_evidence(),
            )
            .and_then(|()| ErasureScopeCommitmentV1::new(admission.scope().clone()))
            .and_then(|scope| {
                ErasureFreezeProvenanceV1::new(ErasureFreezeProvenanceInputV1 {
                    request,
                    scope_commitment: scope.reference(),
                    obligation_set: admission.obligation_set().reference(),
                    freeze_position: admission.freeze_position(),
                    host_evidence: admission.freeze_admission_evidence().reference(),
                })
                .map(|freeze| (scope, freeze))
            })
            .and_then(|(scope, freeze)| {
                scope
                    .lineage_rule()
                    .map(|_| {
                        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
                            scope_commitment: scope.reference(),
                            extensions: Vec::new(),
                            head: None,
                        })
                    })
                    .transpose()
                    .map(|ledger| (scope, freeze, ledger))
            })
            .and_then(|(scope, freeze, ledger)| {
                let replay_claim = record.state.replay_claim();
                record
                    .state
                    .transition(ErasureStateTransitionV1 {
                        lifecycle: ErasureLifecycleV1::AccessFrozen,
                        freeze_position: Some(admission.freeze_position()),
                        pending_owners: Vec::new(),
                        failed_owners: Vec::new(),
                        acknowledged_targets: Vec::new(),
                        replay_claim,
                        provenance: freeze.reference(),
                    })
                    .map(|state| (scope, freeze, ledger, state))
            })
            .and_then(|(scope, freeze, ledger, state)| {
                record.retain_atomic_freeze(state.clone(), admission, scope, freeze, ledger);
                self.commit(record.clone()).map(|()| state)
            })
    }

    fn persist_freeze_rejection(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        failure: ErasureFreezeFailureV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        if failure.request() != record.request.reference()
            || record.authorize_provenance != Some(failure.authorization_provenance())
        {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
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
                provenance: failure.reference(),
            })
            .and_then(|state| {
                record.retain_freeze_failure(state.clone(), failure);
                self.commit(record.clone()).map(|()| state)
            })
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
            if matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
            ) && record.supporting_records.retry_admissions.last() == Some(admission)
            {
                return Ok(record.state);
            }
            let ordinal_index = record.supporting_records.attempt_outcomes.len();
            let source_receipt = record
                .supporting_records
                .receipts
                .last()
                .map(ErasureReceiptV1::receipt_digest);
            u64::try_from(ordinal_index)
                .map_err(|_| ErasureErrorV1::PolicyConflict)
                .and_then(|ordinal| {
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
                    let expected_obligations = Self::unresolved_obligation_references(&record);
                    if admission.unresolved_obligations() != expected_obligations.as_slice() {
                        return Err(ErasureErrorV1::ScopeInvalid);
                    }
                    Self::commands_for_admission(&record, admission).and_then(|commands| {
                        let already_admitted = record
                            .supporting_records
                            .retry_admissions
                            .get(ordinal_index)
                            == Some(admission);
                        let persist_admission = if already_admitted {
                            Ok(())
                        } else {
                            self.port.admit_attempt(admission).and_then(|()| {
                                record
                                    .supporting_records
                                    .retry_admissions
                                    .push(admission.clone());
                                record.acknowledgements = record
                                    .supporting_records
                                    .effective_acknowledgements(admission);
                                if ordinal == 0 {
                                    record.dispatch_provenance = Some(admission.reference());
                                }
                                self.commit(record.clone())
                            })
                        };
                        persist_admission
                            .and_then(|()| self.port.dispatch_destruction(request, &commands))
                            .and_then(|()| {
                                if ordinal != 0 {
                                    return Ok(record.state);
                                }
                                self.persist_initial_dispatch(&mut record, admission)
                            })
                    })
                })
        })
    }

    fn persist_initial_dispatch(
        &mut self,
        record: &mut ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        let freeze_position = record.state.freeze_position();
        let replay_claim = record.state.replay_claim();
        record.state = record.state.transition(ErasureStateTransitionV1 {
            lifecycle: ErasureLifecycleV1::DestructionDispatched,
            freeze_position,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            acknowledged_targets: Vec::new(),
            replay_claim,
            provenance: admission.reference(),
        })?;
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
        self.commit_records(&[dispatched_record, record.clone()])
            .map(|()| record.state.clone())
    }

    fn unresolved_obligation_references(
        record: &ErasureCoordinatorRecordV1,
    ) -> Vec<ErasureReferenceV1> {
        let acknowledged = record
            .acknowledgements
            .iter()
            .filter(|acknowledgement| {
                acknowledgement.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
            })
            .map(|acknowledgement| acknowledgement.obligation)
            .collect::<BTreeSet<_>>();
        record
            .supporting_records
            .obligations()
            .iter()
            .filter(|obligation| !acknowledged.contains(&obligation.reference()))
            .map(ErasureObligationV1::reference)
            .collect()
    }

    fn commands_for_admission(
        record: &ErasureCoordinatorRecordV1,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<Vec<ErasureDestructionCommandV1>, ErasureErrorV1> {
        let obligations = record
            .supporting_records
            .obligations()
            .iter()
            .map(|obligation| (obligation.reference(), obligation))
            .collect::<BTreeMap<_, _>>();
        admission
            .unresolved_obligations()
            .iter()
            .zip(admission.command_identities())
            .try_fold(
                Vec::new(),
                |mut commands, (obligation_reference, command)| {
                    obligations
                        .get(obligation_reference)
                        .copied()
                        .ok_or(ErasureErrorV1::ScopeInvalid)
                        .and_then(|obligation| {
                            if obligation.command_identity() != *command {
                                return Err(ErasureErrorV1::ScopeInvalid);
                            }
                            commands.push(ErasureDestructionCommandV1::from_obligation(
                                obligation,
                                admission.reference(),
                            ));
                            Ok(commands)
                        })
                },
            )
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
        self.record(request).and_then(|record| {
            if matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::DestructionDispatched
                    | ErasureLifecycleV1::AwaitingAcknowledgements
            ) {
                return record
                    .supporting_records
                    .retry_admissions()
                    .last()
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
                    .and_then(|admission| {
                        if admission.authorization_provenance() == provenance {
                            Ok(record.state)
                        } else {
                            Err(ErasureErrorV1::PolicyConflict)
                        }
                    });
            }
            if record.state.lifecycle() != ErasureLifecycleV1::AccessFrozen {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            let obligations = Self::unresolved_obligation_references(&record);
            let command_identities = record
                .supporting_records
                .obligations()
                .iter()
                .map(|obligation| (obligation.reference(), obligation.command_identity()))
                .collect::<BTreeMap<_, _>>();
            obligations
                .iter()
                .map(|reference| {
                    command_identities
                        .get(reference)
                        .copied()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                })
                .collect::<Result<Vec<_>, _>>()
                .and_then(|command_identities| {
                    record
                        .supporting_records
                        .obligation_set()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|obligation_set| (command_identities, obligation_set.trust()))
                })
                .and_then(|(command_identities, trust)| {
                    ErasureRetryAdmissionV1::new(ErasureRetryAdmissionInputV1 {
                        request,
                        attempt_ordinal: 0,
                        source_receipt: None,
                        unresolved_obligations: obligations,
                        command_identities,
                        policy: record.request.policy(),
                        trust,
                        admitted_position: record.request.request_position(),
                        deadline_position: record.request.horizon_position(),
                        authorization_provenance: provenance,
                    })
                })
                .and_then(|admission| self.dispatch_attempt(request, &admission))
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
            if record
                .acknowledgements
                .binary_search(&acknowledgement)
                .is_ok()
            {
                return Ok(record.state);
            }
            if !matches!(
                record.state.lifecycle(),
                ErasureLifecycleV1::AwaitingAcknowledgements | ErasureLifecycleV1::PartialFailure
            ) {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            if record
                .targets
                .binary_search(&acknowledgement.target)
                .is_err()
            {
                return Err(ErasureErrorV1::Unauthorized);
            }
            record
                .supporting_records
                .obligations()
                .binary_search_by_key(&acknowledgement.obligation, ErasureObligationV1::reference)
                .ok()
                .map(|index| &record.supporting_records.obligations()[index])
                .ok_or(ErasureErrorV1::Unauthorized)
                .and_then(|obligation| {
                    if (obligation.target(), obligation.owner())
                        == (acknowledgement.target, acknowledgement.owner)
                    {
                        Ok(obligation.command_identity())
                    } else {
                        Err(ErasureErrorV1::Unauthorized)
                    }
                })
                .and_then(|command| {
                    if record.acknowledgements.iter().any(|existing| {
                        existing.obligation == acknowledgement.obligation
                            && existing.outcome == ErasureAcknowledgementOutcomeV1::Acknowledged
                            && acknowledgement.outcome
                                != ErasureAcknowledgementOutcomeV1::Acknowledged
                    }) {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    record
                        .supporting_records
                        .retry_admissions
                        .last()
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|admission| (command, admission))
                })
                .and_then(|(command, admission)| {
                    let pair_is_admitted = admission
                        .unresolved_obligations()
                        .binary_search(&acknowledgement.obligation)
                        .is_ok_and(|index| admission.command_identities()[index] == command);
                    if !pair_is_admitted {
                        return Err(ErasureErrorV1::Unauthorized);
                    }
                    record
                        .supporting_records
                        .scope_commitment()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|scope| (command, admission, scope.reference()))
                })
                .and_then(|(command, admission, scope)| {
                    ErasureAcknowledgementProvenanceV1::new(
                        ErasureAcknowledgementProvenanceInputV1 {
                            request,
                            command,
                            attempt: admission.reference(),
                            obligation: acknowledgement.obligation,
                            owner: acknowledgement.owner,
                            scope,
                            outcome: acknowledgement.outcome,
                            evidence: acknowledgement.evidence,
                            policy: admission.policy(),
                            trust: admission.trust(),
                        },
                    )
                    .map(|provenance| (admission, provenance))
                })
                .and_then(|(admission, acknowledgement_provenance)| {
                    self.port
                        .admit_acknowledgement(&acknowledgement_provenance)
                        .and_then(|()| {
                            record.retain_acknowledgement(&admission, &acknowledgement_provenance);
                            let state = record.state.clone();
                            self.commit(record).map(|()| state)
                        })
                })
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
        input.frozen_targets.clone_from(&record.targets);
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
            .effective_acknowledgement_provenance(admission)
            .into_iter()
            .map(|(_, provenance)| provenance.reference())
            .collect::<Vec<_>>();
        ErasureAttemptOutcomeV1::new(ErasureAttemptOutcomeInputV1 {
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
        })
        .map(|outcome| (outcome, acknowledgements))
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
        let Some(admission) = record.supporting_records.retry_admissions.last().cloned() else {
            return Err(ErasureErrorV1::ProvenanceMissing);
        };
        if record.supporting_records.retry_admissions.len()
            != record
                .supporting_records
                .attempt_outcomes
                .len()
                .saturating_add(1)
        {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let obligations = record.supporting_records.obligations();
        if !inventories_match_frozen_obligations(&input.inventories, obligations) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        record.acknowledgements = record
            .supporting_records
            .effective_acknowledgements(&admission);
        let complete =
            acknowledgements_close_frozen_obligations(&record.acknowledgements, obligations);
        if !complete && input.issue_position < admission.deadline_position() {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let lifecycle = if complete {
            ErasureLifecycleV1::Complete
        } else {
            ErasureLifecycleV1::PartialFailure
        };
        self.persist_finalization(request, record, input, &admission, lifecycle)
    }

    fn persist_finalization(
        &self,
        request: ErasureReferenceV1,
        record: &mut ErasureCoordinatorRecordV1,
        input: &ErasureReceiptInputV1,
        admission: &ErasureRetryAdmissionV1,
        lifecycle: ErasureLifecycleV1,
    ) -> Result<(ErasureCoordinatorRecordV1, ErasureReceiptV1), ErasureErrorV1> {
        let obligations = record.supporting_records.obligations().to_vec();
        let (pending_owners, failed_owners) =
            derived_outcome_owners_for_obligations(&obligations, &record.acknowledgements);
        let replay_claim = weakest_inventory_claim(&input.inventories);
        let freeze_position = record.state.freeze_position();
        Self::attempt_outcome(record, admission, lifecycle, input.issue_position).and_then(
            |(outcome, acknowledgement_references)| {
                record
                    .state
                    .transition(ErasureStateTransitionV1 {
                        lifecycle,
                        freeze_position,
                        pending_owners,
                        failed_owners,
                        acknowledged_targets: if lifecycle == ErasureLifecycleV1::Complete {
                            record.targets.clone()
                        } else {
                            Vec::new()
                        },
                        replay_claim,
                        provenance: outcome.reference(),
                    })
                    .and_then(|terminal| {
                        Self::receipt_provenance_for_attempt(
                            admission,
                            terminal.state_digest(),
                            &acknowledgement_references,
                            input.issue_position,
                        )
                        .map(|provenance| (terminal, provenance))
                    })
                    .and_then(|(terminal, receipt_provenance)| {
                        record.state = terminal;
                        Self::normalize_receipt_input(
                            request,
                            self.coordinator,
                            record,
                            input.clone(),
                        )
                        .map(|mut normalized| {
                            normalized.policy = admission.policy();
                            normalized.trust = admission.trust();
                            normalized.provenance = receipt_provenance.reference();
                            (normalized, receipt_provenance)
                        })
                    })
                    .and_then(|(normalized, receipt_provenance)| {
                        self.port
                            .admit_receipt(&normalized)
                            .and_then(|()| ErasureReceiptV1::new(normalized.clone()))
                            .and_then(|receipt| {
                                receipt
                                    .validate_frozen_obligations(&obligations)
                                    .map(|()| receipt)
                            })
                            .map(|receipt| (normalized, receipt_provenance, receipt))
                    })
                    .map(|(normalized, receipt_provenance, receipt)| {
                        record.retain_terminal_receipt(
                            normalized,
                            &outcome,
                            receipt.clone(),
                            &receipt_provenance,
                        );
                        (record.clone(), receipt)
                    })
            },
        )
    }

    /// Append one host-admitted scope extension through the persistence CAS seam.
    ///
    /// # Errors
    ///
    /// Returns a closed scope, authorization, or CAS conflict error.
    pub fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|record| {
            record
                .supporting_records
                .scope_commitment()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)
                .and_then(|scope| {
                    scope
                        .lineage_rule()
                        .ok_or(ErasureErrorV1::PolicyConflict)
                        .map(|lineage_rule| (scope, lineage_rule))
                })
                .and_then(|(scope, lineage_rule)| {
                    record
                        .scope_extension_ledger
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|current_reference| (scope, lineage_rule, current_reference))
                })
                .and_then(|(scope, lineage_rule, current_reference)| {
                    record
                        .supporting_records
                        .scope_extension_ledgers()
                        .iter()
                        .find(|ledger| ledger.reference() == current_reference)
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|current| (scope, lineage_rule, current_reference, current))
                })
                .and_then(|(scope, lineage_rule, current_reference, current)| {
                    if current.head() == Some(extension.reference()) {
                        return Ok(record.state);
                    }
                    if (
                        extension.request(),
                        extension.scope_commitment(),
                        extension.lineage_rule(),
                        extension.predecessor_extension(),
                    ) != (request, scope.reference(), lineage_rule, current.head())
                    {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    self.port.admit_scope_extension(&extension).and_then(|()| {
                        let mut extensions = current.extensions().to_vec();
                        extensions.push(extension.reference());
                        ErasureScopeExtensionLedgerV1::new(ErasureScopeExtensionLedgerInputV1 {
                            scope_commitment: scope.reference(),
                            extensions,
                            head: Some(extension.reference()),
                        })
                        .and_then(|successor| {
                            let mut next = record;
                            next.retain_scope_extension(extension, successor);
                            let state = next.state.clone();
                            VerifiedErasureCoordinatorRecordV1::new(next.clone(), &self.port)
                                .and_then(|verified| {
                                    self.port.compare_and_swap_scope_extension(
                                        request,
                                        current_reference,
                                        verified,
                                    )
                                })
                                .map(|()| {
                                    self.cache(next);
                                    state
                                })
                        })
                    })
                })
        })
    }

    /// Append one host-admitted administrative resolution through the CAS seam.
    ///
    /// # Errors
    ///
    /// Returns a closed authorization, commitment, or CAS conflict error.
    pub fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        self.record(request).and_then(|record| {
            record
                .supporting_records
                .scope_commitment()
                .cloned()
                .ok_or(ErasureErrorV1::ProvenanceMissing)
                .and_then(|scope| {
                    record
                        .supporting_records
                        .obligation_set()
                        .cloned()
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .map(|obligation_set| (scope, obligation_set))
                })
                .and_then(|(scope, obligation_set)| {
                    let expected_head = record.administrative_resolution_head;
                    if expected_head == Some(resolution.reference()) {
                        return Ok(record.state);
                    }
                    if (
                        resolution.request(),
                        resolution.scope_commitment(),
                        resolution.policy(),
                        resolution.trust(),
                        resolution.predecessor_resolution(),
                    ) != (
                        request,
                        scope.reference(),
                        record.request.policy(),
                        obligation_set.trust(),
                        expected_head,
                    ) {
                        return Err(ErasureErrorV1::PolicyConflict);
                    }
                    self.port
                        .admit_administrative_resolution(&resolution)
                        .and_then(|()| {
                            let mut next = record;
                            next.retain_administrative_resolution(resolution);
                            let state = next.state.clone();
                            VerifiedErasureCoordinatorRecordV1::new(next.clone(), &self.port)
                                .and_then(|verified| {
                                    self.port.compare_and_swap_administrative_resolution(
                                        request,
                                        expected_head,
                                        verified,
                                    )
                                })
                                .map(|()| {
                                    self.cache(next);
                                    state
                                })
                        })
                })
        })
    }
}

impl<P: ErasureCoordinatorPortV1> ErasureCoordinator for ErasureCoordinatorStateMachineV1<P> {
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1> {
        let provenance = request.provenance();
        Self::submit(self, request, provenance)
    }

    fn submit_corrected(
        &mut self,
        request: ErasureRequestV1,
        correction: ErasureCorrectionProvenanceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::submit_corrected(self, request, correction)
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

    fn append_scope_extension(
        &mut self,
        request: ErasureReferenceV1,
        extension: ErasureScopeExtensionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::append_scope_extension(self, request, extension)
    }

    fn resolve_administratively(
        &mut self,
        request: ErasureReferenceV1,
        resolution: ErasureAdministrativeResolutionV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1> {
        Self::resolve_administratively(self, request, resolution)
    }
}

#[path = "erasure_codec.rs"]
mod codec;
use codec::{
    acknowledgement_provenance_from_fields, acknowledgement_provenance_value,
    acknowledgements_are_closure_subset, administrative_resolution_from_fields,
    administrative_resolution_value, attempt_outcome_from_fields, attempt_outcome_value,
    authorization_rejection_from_fields, authorization_rejection_value,
    correction_provenance_from_fields, correction_provenance_value, decode_limited, domain_digest,
    encode_canonical, encode_limited, exact_array, freeze_admission_authorization_value,
    freeze_admission_evidence_from_fields, freeze_admission_evidence_value,
    freeze_authorization_evidence_from_fields, freeze_authorization_evidence_value,
    freeze_failure_from_fields, freeze_failure_value, freeze_is_monotonic,
    freeze_provenance_from_fields, freeze_provenance_value, has_duplicate,
    has_duplicate_acknowledgement_identity, invalid_owner_sets, inventories_exceed_bound,
    inventories_have_duplicate_targets, inventories_match_closure, inventory_categories_match,
    inventory_transitions_preserve_or_weaken, obligation_from_fields, obligation_set_from_fields,
    obligation_set_value, obligation_value, persistence_manifest_value, receipt_core_value,
    receipt_from_fields, receipt_provenance_from_fields, receipt_provenance_value, receipt_value,
    record_from_fields, record_from_persistence_manifest, record_value, reference_zero,
    request_from_fields, request_value, retry_admission_from_fields, retry_admission_value,
    scope_commitment_from_fields, scope_commitment_value, scope_extension_from_fields,
    scope_extension_ledger_from_fields, scope_extension_ledger_value, scope_extension_value,
    sort_inventories, state_core_value, state_from_fields, state_value, strictly_increasing,
    supporting_records_from_value, supporting_records_value, weakest_inventory_claim,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "erasure_tests.rs"]
mod tests;
