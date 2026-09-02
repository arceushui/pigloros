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
const ERCRP1: &str = "ERCRP1";
const ERASURE_INVENTORY_CATEGORY_COUNT: usize = ErasureInventoryCategoryV1::CANONICAL.len();

/// Largest encoded ERQ1 or ERS1 accepted by V1.
pub const ERASURE_REQUEST_OR_STATE_MAX_BYTES: usize = 1024 * 1024;
/// Largest encoded ERC1 accepted by V1.
pub const ERASURE_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Largest normalized ERCRP1 persistence manifest.
pub const ERASURE_COORDINATOR_RECORD_MAX_BYTES: usize = 1024 * 1024;
/// Largest selector or owner collection accepted by V1.
pub const ERASURE_MAX_REFERENCES: usize = 4_096;
/// Largest number of entries in each ERC1 inventory.
pub const ERASURE_MAX_INVENTORY_RESULTS: usize = 4_096;
/// Largest canonical target closure admitted for one ERQ1.
pub const ERASURE_MAX_TARGETS: usize = 4_096;
/// Largest number of frozen obligations in one category.
pub const ERASURE_MAX_OBLIGATIONS_PER_CATEGORY: usize = 4_096;
/// Largest number of frozen obligations across all categories.
pub const ERASURE_MAX_OBLIGATIONS: usize = 16_384;
/// Largest acknowledgement result set admitted for one attempt.
pub const ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT: usize = 16_384;
/// Largest combined pending- and failed-owner set in ERS1 or ERC1.
pub const ERASURE_MAX_OUTCOME_OWNERS: usize = 16_384;
/// Largest number of immutable scope extensions retained for one ERQ1.
pub const ERASURE_MAX_SCOPE_EXTENSIONS: usize = 4_096;
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
/// Domain tag for the canonical resolved-target closure.
pub const ERASURE_TARGET_CLOSURE_TAG_V1: &str = "ERTC1";
/// Domain tag for one bounded acknowledgement-reference inventory.
pub const ERASURE_ACKNOWLEDGEMENT_INVENTORY_TAG_V1: &str = "ERAI1";
/// Domain tag for one immutable completed-attempt history page.
pub const ERASURE_ATTEMPT_HISTORY_TAG_V1: &str = "ERAH1";
/// Domain tag for one immutable scope-extension head node.
pub const ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1: &str = "ERSEH1";

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
    if !(0..ERASURE_MAX_ATTEMPT_OUTCOMES as u64).contains(&input.attempt_ordinal)
        || (input.attempt_ordinal == 0) != input.source_receipt.is_none()
        || input
            .deadline_position
            .checked_sub(input.admitted_position)
            .is_none()
    {
        return Err(ErasureErrorV1::PolicyConflict);
    }
    if input.unresolved_obligations.len() != input.command_identities.len()
        || input.unresolved_obligations.len() > ERASURE_MAX_OBLIGATIONS
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
    let obligations = pairs
        .iter()
        .map(|(obligation, _)| *obligation)
        .collect::<Vec<_>>();
    if has_duplicate(&obligations) {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    input.unresolved_obligations = obligations;
    input.command_identities = pairs.iter().map(|(_, command)| *command).collect();
    Ok(())
}

// Coordinator recovery intentionally has no aggregate evidence ledger.  The
// authoritative durable shape is ERCRP1 plus independently addressed immutable
// objects.  `persistence` owns the bounded recovered working state.

/// Host-admitted outcome for a submitted ERQ1.
///
/// The decision is part of the authorization-admission key. A host must
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

mod receipt;
pub use receipt::target_closure_digest;
use receipt::{
    acknowledgements_close_frozen_obligations, derived_outcome_owners_for_obligations,
    inventories_match_frozen_obligations,
};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureAcknowledgementOutcomeV1 {
    /// Owner completed scoped work.
    Acknowledged,
    /// Owner could not complete scoped work.
    Negative,
    /// Owner evidence is stale.
    Stale,
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
    /// Frozen target closure; inventory rows cover only applicable obligations.
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

/// Exact stored ERCRP1 bytes and their content address. Adapters return this
/// envelope unchanged; decoding and recovery remain core-owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredErasureManifestV1 {
    digest: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
}

impl StoredErasureManifestV1 {
    /// Construct an adapter-returned manifest after checking its content address.
    ///
    /// # Errors
    ///
    /// Returns [`ErasureErrorV1::ProvenanceMissing`] when `digest` does not
    /// authenticate the supplied canonical ERCRP1 bytes.
    pub fn new(
        digest: ErasureReferenceV1,
        canonical_cbor: Vec<u8>,
    ) -> Result<Self, ErasureErrorV1> {
        (ErasureReferenceV1::from_digest(domain_digest(ERCRP1, &canonical_cbor)) == digest)
            .then_some(Self {
                digest,
                canonical_cbor,
            })
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    /// Return the content address used for CAS.
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.digest
    }

    /// Return the canonical ERCRP1 bytes.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

/// One immutable addressed object inserted by a core-prepared delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasurePersistenceObjectV1 {
    kind: &'static str,
    reference: ErasureReferenceV1,
    canonical_cbor: Vec<u8>,
}

impl ErasurePersistenceObjectV1 {
    pub(crate) fn new(
        kind: &'static str,
        reference: ErasureReferenceV1,
        canonical_cbor: Vec<u8>,
    ) -> Self {
        Self {
            kind,
            reference,
            canonical_cbor,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.reference
    }
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

/// One immutable ERS1 object inserted with a manifest delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasurePersistedStateV1 {
    state: ErasureStateV1,
    canonical_cbor: Vec<u8>,
}

impl ErasurePersistedStateV1 {
    pub(crate) fn new(state: ErasureStateV1, canonical_cbor: Vec<u8>) -> Self {
        Self {
            state,
            canonical_cbor,
        }
    }
    #[must_use]
    pub const fn reference(&self) -> ErasureReferenceV1 {
        self.state.state_digest()
    }
    #[must_use]
    pub const fn state(&self) -> &ErasureStateV1 {
        &self.state
    }
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
}

/// Index rows inserted atomically with their immutable node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureIndexInsertV1 {
    /// `(request, ordinal) -> ERAH1`, unique and non-authoritative.
    AttemptPage {
        ordinal: u64,
        reference: ErasureReferenceV1,
    },
    /// `(request, ordinal) -> ERSEH1`, unique and non-authoritative.
    ScopeNode {
        ordinal: u64,
        reference: ErasureReferenceV1,
    },
    /// `(request, ordinal) -> ERAR1`, unique and non-authoritative.
    AdministrativeResolution {
        ordinal: u64,
        reference: ErasureReferenceV1,
    },
}

/// Adapter effects coupled to one durable manifest advance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErasureCasEffectV1 {
    /// No external admission is consumed by this transition.
    None,
    /// Consume a previously granted quota reservation and create outbox intents.
    AttemptAdmission {
        reservation: ErasureAttemptQuotaReservationV1,
        commands: Vec<ErasureDestructionCommandV1>,
    },
    /// Store the authenticated acknowledgement inbox identity.
    AcknowledgementAdmission { acknowledgement: ErasureReferenceV1 },
    /// Store the admitted receipt identity.
    ReceiptAdmission { receipt: ErasureReferenceV1 },
}

impl ErasureCasEffectV1 {
    /// Return a deterministic identity covering the complete adapter effect.
    #[must_use]
    pub fn identity(&self) -> ErasureReferenceV1 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros/erasure-cas-effect/v1");
        match self {
            Self::None => {
                hasher.update(&[0]);
            }
            Self::AttemptAdmission {
                reservation,
                commands,
            } => {
                hasher.update(&[1]);
                hasher.update(&reservation.admission().digest());
                hasher.update(&reservation.reference().digest());
                hasher.update(&(commands.len() as u64).to_be_bytes());
                for command in commands {
                    hasher.update(&command.obligation.digest());
                    hasher.update(&command.category.code().to_be_bytes());
                    hasher.update(&command.target.artifact_class.code().to_be_bytes());
                    hasher.update(&command.target.artifact_digest.digest());
                    hasher.update(&command.target.key_role.code().to_be_bytes());
                    hasher.update(&command.target.key_digest.digest());
                    hasher.update(&command.target.replica_set.digest());
                    hasher.update(&command.target.replica_id.digest());
                    hasher.update(&command.owner.digest());
                    hasher.update(&command.command.digest());
                    hasher.update(&command.provenance.digest());
                }
            }
            Self::AcknowledgementAdmission { acknowledgement } => {
                hasher.update(&[2]);
                hasher.update(&acknowledgement.digest());
            }
            Self::ReceiptAdmission { receipt } => {
                hasher.update(&[3]);
                hasher.update(&receipt.digest());
            }
        }
        ErasureReferenceV1::from_digest(*hasher.finalize().as_bytes())
    }
}

/// Host-issued, idempotent attempt quota reservation consumed by one CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureAttemptQuotaReservationV1 {
    admission: ErasureReferenceV1,
    reference: ErasureReferenceV1,
}

impl ErasureAttemptQuotaReservationV1 {
    /// Construct a host-issued reservation capability.
    #[must_use]
    pub const fn new(admission: ErasureReferenceV1, reference: ErasureReferenceV1) -> Self {
        Self {
            admission,
            reference,
        }
    }
    /// Return the admission identity this reservation authorizes.
    #[must_use]
    pub const fn admission(self) -> ErasureReferenceV1 {
        self.admission
    }
    /// Return the durable reservation identity.
    #[must_use]
    pub const fn reference(self) -> ErasureReferenceV1 {
        self.reference
    }
}

/// Opaque core-prepared, append-only ERCRP1 delta. Adapters inspect getters
/// only and must not decode or reconstruct recovered coordinator state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedErasureCasV1 {
    request: ErasureReferenceV1,
    expected_manifest_digest: Option<ErasureReferenceV1>,
    next_manifest: StoredErasureManifestV1,
    new_objects: Vec<ErasurePersistenceObjectV1>,
    new_states: Vec<ErasurePersistedStateV1>,
    index_inserts: Vec<ErasureIndexInsertV1>,
    effect: ErasureCasEffectV1,
}

impl PreparedErasureCasV1 {
    pub(crate) fn new(
        request: ErasureReferenceV1,
        expected_manifest_digest: Option<ErasureReferenceV1>,
        next_manifest: StoredErasureManifestV1,
        new_objects: Vec<ErasurePersistenceObjectV1>,
        new_states: Vec<ErasurePersistedStateV1>,
        index_inserts: Vec<ErasureIndexInsertV1>,
        effect: ErasureCasEffectV1,
    ) -> Self {
        Self {
            request,
            expected_manifest_digest,
            next_manifest,
            new_objects,
            new_states,
            index_inserts,
            effect,
        }
    }
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.request
    }
    #[must_use]
    pub const fn expected_manifest_digest(&self) -> Option<ErasureReferenceV1> {
        self.expected_manifest_digest
    }
    #[must_use]
    pub const fn next_manifest(&self) -> &StoredErasureManifestV1 {
        &self.next_manifest
    }
    #[must_use]
    pub fn new_objects(&self) -> &[ErasurePersistenceObjectV1] {
        &self.new_objects
    }
    #[must_use]
    pub fn new_states(&self) -> &[ErasurePersistedStateV1] {
        &self.new_states
    }
    #[must_use]
    pub fn index_inserts(&self) -> &[ErasureIndexInsertV1] {
        &self.index_inserts
    }
    #[must_use]
    pub const fn effect(&self) -> &ErasureCasEffectV1 {
        &self.effect
    }
}

/// Result of applying a core-prepared manifest delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureCasOutcomeV1 {
    Applied,
    ExactRetry,
}

/// Raw persistence SPI. The core owns ERCRP1 decoding, recovery, validation,
/// and construction of every mutation. Adapters own only canonical byte/object
/// storage and one atomic compare-and-swap transaction.
pub trait ErasurePersistencePortV1: ErasureStateResolverV1 {
    /// Return the current ERCRP1 envelope for one request, if any.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read or decoding error.
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<StoredErasureManifestV1>, ErasureErrorV1>;
    /// Return one immutable object by content address.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error for an unavailable object.
    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1>;
    /// Return the non-authoritative ERAH1 ordinal-index entry.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn attempt_page_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1>;
    /// Return the exact ERAH1 ordinal-index cardinality.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn attempt_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1>;
    /// Return the non-authoritative ERSEH1 ordinal-index entry.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn scope_node_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1>;
    /// Return the number of indexed ERSEH1 nodes for one request.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn scope_index_count(&self, request: ErasureReferenceV1) -> Result<u64, ErasureErrorV1>;
    /// Return the non-authoritative administrative-resolution index entry.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn administrative_resolution_ref(
        &self,
        request: ErasureReferenceV1,
        ordinal: u64,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1>;
    /// Return the number of indexed administrative-resolution records.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter read error.
    fn administrative_resolution_index_count(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<u64, ErasureErrorV1>;
    /// Atomically apply a core-prepared delta. If the current manifest already
    /// equals the supplied next manifest and every referenced delta is equal,
    /// return [`ErasureCasOutcomeV1::ExactRetry`]; otherwise stale heads fail
    /// closed with [`ErasureErrorV1::PolicyConflict`].
    ///
    /// # Errors
    ///
    /// Returns a closed transaction error or [`ErasureErrorV1::PolicyConflict`]
    /// for a non-identical stale manifest head.
    fn compare_and_swap(
        &mut self,
        mutation: PreparedErasureCasV1,
    ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1>;
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
    /// Returns an idempotent quota reservation which the core places in the
    /// prepared CAS effect. The adapter consumes that exact reservation when
    /// it persists the active attempt and durable outbox intents, so refusal
    /// happens before any state/object/outbox delta is constructed.
    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1>;
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

mod persistence;
pub(crate) use persistence::RecoveredErasureV1;
/// Core-owned, idempotent ERQ1/ERS1/ERC1 state machine; adapters cannot bypass it.
pub struct ErasureCoordinatorStateMachineV1<P> {
    port: P,
    coordinator: ErasureReferenceV1,
    records: Vec<RecoveredErasureV1>,
}

#[path = "erasure_codec.rs"]
mod codec;
mod coordinator;
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
    has_duplicate_acknowledgement_identity, invalid_owner_sets, inventories_are_within_closure,
    inventories_exceed_bound, inventories_have_duplicate_targets, inventory_categories_match,
    inventory_transitions_preserve_or_weaken, obligation_from_fields, obligation_set_from_fields,
    obligation_set_value, obligation_value, receipt_core_value, receipt_from_fields,
    receipt_provenance_from_fields, receipt_provenance_value, receipt_value, reference_zero,
    request_from_fields, request_value, retry_admission_from_fields, retry_admission_value,
    scope_commitment_from_fields, scope_commitment_value, scope_extension_from_fields,
    scope_extension_value, sort_inventories, state_core_value, state_from_fields, state_value,
    strictly_increasing, weakest_inventory_claim,
};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "erasure_tests.rs"]
pub mod tests;
