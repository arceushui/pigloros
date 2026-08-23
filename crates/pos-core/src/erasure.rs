//! Subject-erasure contracts required by ADR-060.
//!
//! This module deliberately owns no storage, authentication implementation, or
//! deletion adapter.  It defines the small core seam through which a host can
//! coordinate an erasure while preserving only structural evidence.

use std::{cmp::Ordering, io::Cursor};

use ciborium::value::Value;

use crate::Hash;

/// The largest permitted encoded ERQ1 or ERS1 contract.
pub const ERASURE_REQUEST_OR_STATE_MAX_BYTES: usize = 1024 * 1024;
/// The largest permitted encoded ERC1 contract.
pub const ERASURE_RECEIPT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// The maximum number of minimized selectors in one request.
pub const ERASURE_MAX_SELECTORS: usize = 4_096;
/// The maximum number of acknowledgement records in one receipt category.
pub const ERASURE_MAX_RECEIPTS: usize = 65_536;

const ERQ1: &str = "ERQ1";
const ERS1: &str = "ERS1";
const ERC1: &str = "ERC1";
const V1: u64 = 1;

/// Closed errors that may cross the erasure coordinator seam.
///
/// These codes intentionally never contain deleted payload, unbounded adapter
/// diagnostics, key material, or an identity more specific than a request
/// reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErasureErrorV1 {
    InvalidEncoding,
    UnsupportedVersion,
    Unauthorized,
    ScopeInvalid,
    PolicyConflict,
    AccessFreezeFailed,
    KeyRegistryUnavailable,
    KeyDestructionFailed,
    ArtifactDeletionFailed,
    ReplicaTimeout,
    ReplicaNegativeAcknowledgement,
    BackupInventoryIncomplete,
    BackupDeletionPending,
    ReceiptCommitFailed,
    TrustSnapshotInvalid,
    ProvenanceMissing,
}

impl ErasureErrorV1 {
    /// Stable closed code for deterministic transport or persistence.
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

    /// Decode a stable closed code without accepting vendor-defined errors.
    ///
    /// # Errors
    ///
    /// Returns [`Self::InvalidEncoding`] for an unknown code.
    pub fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
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
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid erasure encoding",
            Self::UnsupportedVersion => "unsupported erasure version",
            Self::Unauthorized => "erasure request unauthorized",
            Self::ScopeInvalid => "erasure scope invalid",
            Self::PolicyConflict => "erasure policy conflict",
            Self::AccessFreezeFailed => "erasure access freeze failed",
            Self::KeyRegistryUnavailable => "erasure key registry unavailable",
            Self::KeyDestructionFailed => "erasure key destruction failed",
            Self::ArtifactDeletionFailed => "erasure artifact deletion failed",
            Self::ReplicaTimeout => "erasure replica timed out",
            Self::ReplicaNegativeAcknowledgement => "erasure replica negatively acknowledged",
            Self::BackupInventoryIncomplete => "erasure backup inventory incomplete",
            Self::BackupDeletionPending => "erasure backup deletion pending",
            Self::ReceiptCommitFailed => "erasure receipt commit failed",
            Self::TrustSnapshotInvalid => "erasure trust snapshot invalid",
            Self::ProvenanceMissing => "erasure provenance missing",
        })
    }
}

impl std::error::Error for ErasureErrorV1 {}

/// A minimized, fixed-length digest reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ErasureReferenceV1([u8; 32]);

impl ErasureReferenceV1 {
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

impl From<Hash> for ErasureReferenceV1 {
    fn from(value: Hash) -> Self {
        Self(*value.as_bytes())
    }
}

/// A bounded, non-enumerating selector.  It contains only an irreversible
/// scope commitment and never a Timeline payload, subject attribute, or key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ErasureSelectorV1 {
    selector_digest: ErasureReferenceV1,
}

impl ErasureSelectorV1 {
    #[must_use]
    pub const fn from_digest(selector_digest: ErasureReferenceV1) -> Self {
        Self { selector_digest }
    }

    #[must_use]
    pub const fn digest(self) -> ErasureReferenceV1 {
        self.selector_digest
    }
}

/// Closed classes whose inventory is included in an erasure request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErasureScopeV1 {
    PrivateSubjectData,
    ConsentedSharedData,
    PublicRecord,
    AggregateData,
    StructuralAuditMetadata,
}

impl ErasureScopeV1 {
    const fn code(self) -> u64 {
        match self {
            Self::PrivateSubjectData => 0,
            Self::ConsentedSharedData => 1,
            Self::PublicRecord => 2,
            Self::AggregateData => 3,
            Self::StructuralAuditMetadata => 4,
        }
    }

    fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::PrivateSubjectData),
            1 => Ok(Self::ConsentedSharedData),
            2 => Ok(Self::PublicRecord),
            3 => Ok(Self::AggregateData),
            4 => Ok(Self::StructuralAuditMetadata),
            _ => Err(ErasureErrorV1::ScopeInvalid),
        }
    }
}

/// The lifecycle states defined by ADR-060. Their ordinal is the authority for
/// monotonicity; enum declaration order is never used as a protocol rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErasureLifecycleV1 {
    Submitted,
    Authorized,
    AccessFrozen,
    DestructionDispatched,
    AwaitingAcknowledgements,
    Complete,
    PartialFailure,
    Rejected,
}

impl ErasureLifecycleV1 {
    #[must_use]
    pub const fn ordinal(self) -> u8 {
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

    const fn code(self) -> u64 {
        self.ordinal() as u64
    }

    fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
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

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::PartialFailure | Self::Rejected)
    }

    /// Whether this exact edge is a legal monotonic lifecycle transition.
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Submitted, Self::Authorized | Self::Rejected)
                | (Self::Authorized, Self::AccessFrozen | Self::Rejected)
                | (
                    Self::AccessFrozen,
                    Self::DestructionDispatched | Self::PartialFailure
                )
                | (
                    Self::DestructionDispatched,
                    Self::AwaitingAcknowledgements | Self::PartialFailure
                )
                | (
                    Self::AwaitingAcknowledgements,
                    Self::Complete | Self::PartialFailure
                )
        )
    }
}

/// The no-payload result for one required owner acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ErasureAcknowledgementV1 {
    owner: ErasureReferenceV1,
    acknowledgement: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
}

impl ErasureAcknowledgementV1 {
    #[must_use]
    pub const fn new(
        owner: ErasureReferenceV1,
        acknowledgement: ErasureReferenceV1,
        outcome: ErasureAcknowledgementOutcomeV1,
    ) -> Self {
        Self {
            owner,
            acknowledgement,
            outcome,
        }
    }

    #[must_use]
    pub const fn owner(self) -> ErasureReferenceV1 {
        self.owner
    }
    #[must_use]
    /// Return the opaque acknowledgement commitment.
    pub const fn acknowledgement(self) -> ErasureReferenceV1 {
        self.acknowledgement
    }
    #[must_use]
    pub const fn outcome(self) -> ErasureAcknowledgementOutcomeV1 {
        self.outcome
    }
}

/// Closed acknowledgement outcomes. Missing acknowledgements are represented by
/// their absence from the receipt, not a fabricated acknowledgement record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErasureAcknowledgementOutcomeV1 {
    Acknowledged,
    Negative,
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
    fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Acknowledged),
            1 => Ok(Self::Negative),
            2 => Ok(Self::Stale),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

/// Exact ERQ1 request. Every reference is a digest so the request cannot be an
/// inventory or a transport for content proposed for erasure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureRequestV1 {
    request: ErasureReferenceV1,
    subject: ErasureReferenceV1,
    scope: ErasureScopeV1,
    selectors: Vec<ErasureSelectorV1>,
    requester: ErasureReferenceV1,
    authorization: ErasureReferenceV1,
    policy: ErasureReferenceV1,
    request_position: u64,
    horizon_position: u64,
    provenance: ErasureReferenceV1,
}

impl ErasureRequestV1 {
    /// Build a validated ERQ1 request with canonically ordered selectors.
    pub fn new(
        request: ErasureReferenceV1,
        subject: ErasureReferenceV1,
        scope: ErasureScopeV1,
        mut selectors: Vec<ErasureSelectorV1>,
        requester: ErasureReferenceV1,
        authorization: ErasureReferenceV1,
        policy: ErasureReferenceV1,
        request_position: u64,
        horizon_position: u64,
        provenance: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        if selectors.is_empty()
            || selectors.len() > ERASURE_MAX_SELECTORS
            || request_position > horizon_position
        {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        selectors.sort_unstable();
        if selectors.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        Ok(Self {
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
    }

    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.request
    }
    #[must_use]
    pub const fn scope(&self) -> ErasureScopeV1 {
        self.scope
    }
    #[must_use]
    pub fn selectors(&self) -> impl ExactSizeIterator<Item = ErasureSelectorV1> + '_ {
        self.selectors.iter().copied()
    }

    /// Encode the exact-length, deterministic ERQ1 array.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        let value = Value::Array(vec![
            text(ERQ1),
            uint(V1),
            digest(self.request),
            digest(self.subject),
            uint(self.scope.code()),
            Value::Array(
                self.selectors
                    .iter()
                    .map(|selector| digest(selector.digest()))
                    .collect(),
            ),
            digest(self.requester),
            digest(self.authorization),
            digest(self.policy),
            uint(self.request_position),
            uint(self.horizon_position),
            digest(self.provenance),
        ]);
        encode_limited(&value, ERASURE_REQUEST_OR_STATE_MAX_BYTES)
    }

    /// Decode ERQ1 without upcasting or inventing authorization/provenance.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        let value = decode_limited(bytes, ERASURE_REQUEST_OR_STATE_MAX_BYTES)?;
        let fields = exact_array(&value, 12)?;
        if string(&fields[0])? != ERQ1 || unsigned(&fields[1])? != V1 {
            return Err(ErasureErrorV1::UnsupportedVersion);
        }
        let selectors = array(&fields[5], ERASURE_MAX_SELECTORS)?
            .iter()
            .map(|value| bytes32(value).map(ErasureSelectorV1::from_digest))
            .collect::<Result<Vec<_>, _>>();
        let selectors = selectors?;
        if !strictly_increasing(&selectors) {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        let request = Self::new(
            bytes32(&fields[2])?,
            bytes32(&fields[3])?,
            ErasureScopeV1::from_code(unsigned(&fields[4])?)?,
            selectors,
            bytes32(&fields[6])?,
            bytes32(&fields[7])?,
            bytes32(&fields[8])?,
            unsigned(&fields[9])?,
            unsigned(&fields[10])?,
            bytes32(&fields[11])?,
        );
        request
    }
}

/// Exact ERS1 monotonic lifecycle state.  It carries structural references
/// only; a host resolves references through its protected adapters.
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
    state_digest: ErasureReferenceV1,
}

/// Erasure's closed ReplayClaim representation, kept in core to avoid making a
/// core port depend on a conformance adapter crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ErasureReplayClaimV1 {
    Exact,
    ExactAuthoritativeWithRedactedViews,
    StructuralOnly,
    UnverifiableArtifactsMissing,
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
    fn from_code(code: u64) -> Result<Self, ErasureErrorV1> {
        match code {
            0 => Ok(Self::Exact),
            1 => Ok(Self::ExactAuthoritativeWithRedactedViews),
            2 => Ok(Self::StructuralOnly),
            3 => Ok(Self::UnverifiableArtifactsMissing),
            4 => Ok(Self::IncompatibleProfile),
            _ => Err(ErasureErrorV1::InvalidEncoding),
        }
    }
}

impl ErasureStateV1 {
    /// Create the sole digest-bound initial state for a request.
    ///
    /// # Errors
    ///
    /// Returns a closed encoding error if the initial structural evidence cannot
    /// be represented as ERS1.
    pub fn submitted(
        request: ErasureReferenceV1,
        coordinator: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        let state = Self {
            request,
            lifecycle: ErasureLifecycleV1::Submitted,
            freeze_position: None,
            coordinator,
            pending_owners: Vec::new(),
            failed_owners: Vec::new(),
            replay_claim: ErasureReplayClaimV1::Exact,
            previous_state: None,
            state_digest: ErasureReferenceV1::from_digest([0; 32]),
        };
        state.with_digest()
    }

    #[must_use]
    pub const fn lifecycle(&self) -> ErasureLifecycleV1 {
        self.lifecycle
    }
    #[must_use]
    pub const fn request(&self) -> ErasureReferenceV1 {
        self.request
    }
    #[must_use]
    pub const fn freeze_position(&self) -> Option<u64> {
        self.freeze_position
    }
    #[must_use]
    pub fn pending_owners(&self) -> impl ExactSizeIterator<Item = ErasureReferenceV1> + '_ {
        self.pending_owners.iter().copied()
    }
    #[must_use]
    pub fn failed_owners(&self) -> impl ExactSizeIterator<Item = ErasureReferenceV1> + '_ {
        self.failed_owners.iter().copied()
    }

    /// Make one valid forward transition.  `Complete` is available only after
    /// every required owner has supplied a positive acknowledgement.
    pub fn transition(
        &self,
        next: ErasureLifecycleV1,
        freeze_position: Option<u64>,
        pending_owners: Vec<ErasureReferenceV1>,
        failed_owners: Vec<ErasureReferenceV1>,
        replay_claim: ErasureReplayClaimV1,
        previous_state: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        if !self.lifecycle.permits(next) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let state = Self {
            request: self.request,
            lifecycle: next,
            freeze_position,
            coordinator: self.coordinator,
            pending_owners: canonical_references(pending_owners)?,
            failed_owners: canonical_references(failed_owners)?,
            replay_claim,
            previous_state: Some(previous_state),
            state_digest: ErasureReferenceV1::from_digest([0; 32]),
        };
        state.validate_lifecycle()?;
        Ok(state.with_digest()?)
    }

    fn with_digest(mut self) -> Result<Self, ErasureErrorV1> {
        let bytes = self.encode_without_digest()?;
        self.state_digest =
            ErasureReferenceV1::from_digest(domain_digest(b"PiglorOS.ERS1.state.v1", &bytes));
        Ok(self)
    }

    fn validate_lifecycle(&self) -> Result<(), ErasureErrorV1> {
        let frozen = self.freeze_position.is_some();
        let has_valid_predecessor = match self.lifecycle {
            ErasureLifecycleV1::Submitted => self.previous_state.is_none(),
            _ => self.previous_state.is_some(),
        };
        let valid = match self.lifecycle {
            ErasureLifecycleV1::Submitted
            | ErasureLifecycleV1::Authorized
            | ErasureLifecycleV1::Rejected => {
                !frozen && self.pending_owners.is_empty() && self.failed_owners.is_empty()
            }
            ErasureLifecycleV1::AccessFrozen => {
                frozen && self.pending_owners.is_empty() && self.failed_owners.is_empty()
            }
            ErasureLifecycleV1::DestructionDispatched
            | ErasureLifecycleV1::AwaitingAcknowledgements => frozen,
            ErasureLifecycleV1::Complete => {
                frozen && self.pending_owners.is_empty() && self.failed_owners.is_empty()
            }
            ErasureLifecycleV1::PartialFailure => {
                frozen && (!self.pending_owners.is_empty() || !self.failed_owners.is_empty())
            }
        };
        if valid && has_valid_predecessor {
            Ok(())
        } else {
            Err(ErasureErrorV1::PolicyConflict)
        }
    }

    fn encode_without_digest(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(&self.value(false), ERASURE_REQUEST_OR_STATE_MAX_BYTES)
    }

    fn value(&self, include_digest: bool) -> Value {
        let mut values = vec![
            text(ERS1),
            uint(V1),
            digest(self.request),
            uint(self.lifecycle.code()),
            optional_uint(self.freeze_position),
            digest(self.coordinator),
            Value::Array(self.pending_owners.iter().copied().map(digest).collect()),
            Value::Array(self.failed_owners.iter().copied().map(digest).collect()),
            uint(self.replay_claim.code()),
            optional_digest(self.previous_state),
        ];
        if include_digest {
            values.push(digest(self.state_digest));
        }
        Value::Array(values)
    }

    /// Encode the exact-length deterministic ERS1 array.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate_lifecycle()?;
        let expected = self.clone().with_digest()?.state_digest;
        if self.state_digest != expected {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        encode_limited(&self.value(true), ERASURE_REQUEST_OR_STATE_MAX_BYTES)
    }

    /// Decode an ERS1 state.  V1 refuses an invalid or non-monotonic state;
    /// migration must retain its old receipt instead of manufacturing evidence.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        let value = decode_limited(bytes, ERASURE_REQUEST_OR_STATE_MAX_BYTES)?;
        let fields = exact_array(&value, 11)?;
        if string(&fields[0])? != ERS1 || unsigned(&fields[1])? != V1 {
            return Err(ErasureErrorV1::UnsupportedVersion);
        }
        let pending_owners = references(&fields[6])?;
        let failed_owners = references(&fields[7])?;
        let state = Self {
            request: bytes32(&fields[2])?,
            lifecycle: ErasureLifecycleV1::from_code(unsigned(&fields[3])?)?,
            freeze_position: optional_unsigned(&fields[4])?,
            coordinator: bytes32(&fields[5])?,
            pending_owners,
            failed_owners,
            replay_claim: ErasureReplayClaimV1::from_code(unsigned(&fields[8])?)?,
            previous_state: optional_bytes32(&fields[9])?,
            state_digest: bytes32(&fields[10])?,
        };
        state.validate_lifecycle()?;
        let expected = state.clone().with_digest()?.state_digest;
        if state.state_digest == expected {
            Ok(state)
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
}

/// One payload-free artifact/key/replica/backup result.  The six fields are
/// ordered bytewise as mandated by ADR-060, independent of arrival order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureArtifactResultV1 {
    artifact_class: u8,
    artifact_digest: ErasureReferenceV1,
    key_role: u8,
    key_digest: ErasureReferenceV1,
    replica_set: ErasureReferenceV1,
    replica_id: ErasureReferenceV1,
    outcome: ErasureAcknowledgementOutcomeV1,
}

impl ErasureArtifactResultV1 {
    #[must_use]
    pub const fn new(
        artifact_class: u8,
        artifact_digest: ErasureReferenceV1,
        key_role: u8,
        key_digest: ErasureReferenceV1,
        replica_set: ErasureReferenceV1,
        replica_id: ErasureReferenceV1,
        outcome: ErasureAcknowledgementOutcomeV1,
    ) -> Self {
        Self {
            artifact_class,
            artifact_digest,
            key_role,
            key_digest,
            replica_set,
            replica_id,
            outcome,
        }
    }

    fn value(self) -> Value {
        Value::Array(vec![
            uint(u64::from(self.artifact_class)),
            digest(self.artifact_digest),
            uint(u64::from(self.key_role)),
            digest(self.key_digest),
            digest(self.replica_set),
            digest(self.replica_id),
            uint(self.outcome.code()),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ErasureErrorV1> {
        let values = exact_array(value, 7)?;
        let artifact_class =
            u8::try_from(unsigned(&values[0])?).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
        let key_role =
            u8::try_from(unsigned(&values[2])?).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
        Ok(Self::new(
            artifact_class,
            bytes32(&values[1])?,
            key_role,
            bytes32(&values[3])?,
            bytes32(&values[4])?,
            bytes32(&values[5])?,
            ErasureAcknowledgementOutcomeV1::from_code(unsigned(&values[6])?)?,
        ))
    }
}

impl Ord for ErasureArtifactResultV1 {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.artifact_class,
            self.artifact_digest,
            self.key_role,
            self.key_digest,
            self.replica_set,
            self.replica_id,
        )
            .cmp(&(
                other.artifact_class,
                other.artifact_digest,
                other.key_role,
                other.key_digest,
                other.replica_set,
                other.replica_id,
            ))
    }
}
impl PartialOrd for ErasureArtifactResultV1 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Exact terminal ERC1 receipt. It describes only commitments and outcomes;
/// neither the erased bytes nor an enumeration of subject data can enter it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureReceiptV1 {
    request: ErasureReferenceV1,
    terminal: ErasureLifecycleV1,
    freeze_position: u64,
    artifact_results: Vec<ErasureArtifactResultV1>,
    key_results: Vec<ErasureArtifactResultV1>,
    replica_results: Vec<ErasureArtifactResultV1>,
    backup_results: Vec<ErasureArtifactResultV1>,
    retained_disclosures: Vec<ErasureReferenceV1>,
    policy: ErasureReferenceV1,
    trust: ErasureReferenceV1,
    provenance: ErasureReferenceV1,
    issue_position: u64,
    receipt_digest: ErasureReferenceV1,
    signature: ErasureReferenceV1,
}

impl ErasureReceiptV1 {
    /// Construct a receipt, canonically sorting every result collection. A
    /// Complete receipt must account for all required acknowledgements.
    pub fn new(
        request: ErasureReferenceV1,
        terminal: ErasureLifecycleV1,
        freeze_position: u64,
        artifact_results: Vec<ErasureArtifactResultV1>,
        key_results: Vec<ErasureArtifactResultV1>,
        replica_results: Vec<ErasureArtifactResultV1>,
        backup_results: Vec<ErasureArtifactResultV1>,
        retained_disclosures: Vec<ErasureReferenceV1>,
        policy: ErasureReferenceV1,
        trust: ErasureReferenceV1,
        provenance: ErasureReferenceV1,
        issue_position: u64,
        signature: ErasureReferenceV1,
    ) -> Result<Self, ErasureErrorV1> {
        if !matches!(
            terminal,
            ErasureLifecycleV1::Complete
                | ErasureLifecycleV1::PartialFailure
                | ErasureLifecycleV1::Rejected
        ) {
            return Err(ErasureErrorV1::PolicyConflict);
        }
        let mut receipt = Self {
            request,
            terminal,
            freeze_position,
            artifact_results: canonical_results(artifact_results)?,
            key_results: canonical_results(key_results)?,
            replica_results: canonical_results(replica_results)?,
            backup_results: canonical_results(backup_results)?,
            retained_disclosures: canonical_references(retained_disclosures)?,
            policy,
            trust,
            provenance,
            issue_position,
            receipt_digest: ErasureReferenceV1::from_digest([0; 32]),
            signature,
        };
        receipt.validate_completion()?;
        receipt.receipt_digest = ErasureReferenceV1::from_digest(domain_digest(
            b"PiglorOS.ERC1.receipt.v1",
            &receipt.encode_without_digest()?,
        ));
        Ok(receipt)
    }

    #[must_use]
    pub const fn terminal(&self) -> ErasureLifecycleV1 {
        self.terminal
    }
    #[must_use]
    pub const fn digest(&self) -> ErasureReferenceV1 {
        self.receipt_digest
    }
    #[must_use]
    pub fn artifact_results(&self) -> impl ExactSizeIterator<Item = ErasureArtifactResultV1> + '_ {
        self.artifact_results.iter().copied()
    }

    fn validate_completion(&self) -> Result<(), ErasureErrorV1> {
        let all_results = self
            .artifact_results
            .iter()
            .chain(&self.key_results)
            .chain(&self.replica_results)
            .chain(&self.backup_results);
        let has_failure = all_results
            .clone()
            .any(|result| result.outcome != ErasureAcknowledgementOutcomeV1::Acknowledged);
        let has_any = all_results.count() != 0;
        match self.terminal {
            ErasureLifecycleV1::Complete if !has_any || has_failure => {
                Err(ErasureErrorV1::ReplicaNegativeAcknowledgement)
            }
            ErasureLifecycleV1::PartialFailure if !has_failure => {
                Err(ErasureErrorV1::PolicyConflict)
            }
            ErasureLifecycleV1::Rejected if has_any => Err(ErasureErrorV1::PolicyConflict),
            ErasureLifecycleV1::Complete
            | ErasureLifecycleV1::PartialFailure
            | ErasureLifecycleV1::Rejected => Ok(()),
            _ => Err(ErasureErrorV1::PolicyConflict),
        }
    }

    fn value(&self, include_digest: bool) -> Value {
        let mut values = vec![
            text(ERC1),
            uint(V1),
            digest(self.request),
            uint(self.terminal.code()),
            uint(self.freeze_position),
            Value::Array(
                self.artifact_results
                    .iter()
                    .copied()
                    .map(ErasureArtifactResultV1::value)
                    .collect(),
            ),
            Value::Array(
                self.key_results
                    .iter()
                    .copied()
                    .map(ErasureArtifactResultV1::value)
                    .collect(),
            ),
            Value::Array(
                self.replica_results
                    .iter()
                    .copied()
                    .map(ErasureArtifactResultV1::value)
                    .collect(),
            ),
            Value::Array(
                self.backup_results
                    .iter()
                    .copied()
                    .map(ErasureArtifactResultV1::value)
                    .collect(),
            ),
            Value::Array(
                self.retained_disclosures
                    .iter()
                    .copied()
                    .map(digest)
                    .collect(),
            ),
            digest(self.policy),
            digest(self.trust),
            digest(self.provenance),
            uint(self.issue_position),
        ];
        if include_digest {
            values.push(digest(self.receipt_digest));
        }
        values.push(digest(self.signature));
        Value::Array(values)
    }

    fn encode_without_digest(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        encode_limited(&self.value(false), ERASURE_RECEIPT_MAX_BYTES)
    }

    /// Encode the exact-length deterministic ERC1 array.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ErasureErrorV1> {
        self.validate_completion()?;
        let expected = ErasureReferenceV1::from_digest(domain_digest(
            b"PiglorOS.ERC1.receipt.v1",
            &self.encode_without_digest()?,
        ));
        if self.receipt_digest != expected {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        encode_limited(&self.value(true), ERASURE_RECEIPT_MAX_BYTES)
    }

    /// Decode ERC1 without allowing a newer shape to be interpreted as V1.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ErasureErrorV1> {
        let value = decode_limited(bytes, ERASURE_RECEIPT_MAX_BYTES)?;
        let fields = exact_array(&value, 16)?;
        if string(&fields[0])? != ERC1 || unsigned(&fields[1])? != V1 {
            return Err(ErasureErrorV1::UnsupportedVersion);
        }
        let receipt = Self {
            request: bytes32(&fields[2])?,
            terminal: ErasureLifecycleV1::from_code(unsigned(&fields[3])?)?,
            freeze_position: unsigned(&fields[4])?,
            artifact_results: results(&fields[5])?,
            key_results: results(&fields[6])?,
            replica_results: results(&fields[7])?,
            backup_results: results(&fields[8])?,
            retained_disclosures: references(&fields[9])?,
            policy: bytes32(&fields[10])?,
            trust: bytes32(&fields[11])?,
            provenance: bytes32(&fields[12])?,
            issue_position: unsigned(&fields[13])?,
            receipt_digest: bytes32(&fields[14])?,
            signature: bytes32(&fields[15])?,
        };
        receipt.validate_completion()?;
        let expected = ErasureReferenceV1::from_digest(domain_digest(
            b"PiglorOS.ERC1.receipt.v1",
            &receipt.encode_without_digest()?,
        ));
        if receipt.receipt_digest == expected {
            Ok(receipt)
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }
}

/// Host-owned port for the complete ADR-060 lifecycle. Implementors perform
/// authentication, access freezing, owner dispatch, and durable receipt commit;
/// callers cannot skip those checks by manipulating a state directly.
pub trait ErasureCoordinator {
    /// Return the submitted state for a new request, or its existing state for
    /// the same request reference. Different scope/authorization under the same
    /// request reference must return `PolicyConflict`.
    fn submit(&mut self, request: ErasureRequestV1) -> Result<ErasureStateV1, ErasureErrorV1>;

    /// Advance a submitted request through host authentication and policy
    /// resolution. An existing authorization retry is idempotent.
    fn authorize(&mut self, request: ErasureReferenceV1) -> Result<ErasureStateV1, ErasureErrorV1>;

    /// Freeze subject access at a host-owned Tick Boundary. Repeating the same
    /// successful call must not create another freeze or alter its position.
    fn freeze_access(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;

    /// Dispatch idempotent deletion commands to the registered owner closure.
    fn dispatch_destruction(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;

    /// Record a signed, structurally bounded owner acknowledgement. Arrival
    /// order cannot affect the eventual ERC1 ordering.
    fn acknowledge(
        &mut self,
        request: ErasureReferenceV1,
        acknowledgement: ErasureAcknowledgementV1,
    ) -> Result<ErasureStateV1, ErasureErrorV1>;

    /// Produce and durably commit an ERC1 terminal receipt. Missing, stale, or
    /// negative required acknowledgements result in `PartialFailure`.
    fn finalize(&mut self, request: ErasureReferenceV1)
        -> Result<ErasureReceiptV1, ErasureErrorV1>;
}

fn canonical_references(
    mut references: Vec<ErasureReferenceV1>,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    if references.len() > ERASURE_MAX_RECEIPTS {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    references.sort_unstable();
    if references.windows(2).any(|pair| pair[0] == pair[1]) {
        Err(ErasureErrorV1::ScopeInvalid)
    } else {
        Ok(references)
    }
}

fn canonical_results(
    mut results: Vec<ErasureArtifactResultV1>,
) -> Result<Vec<ErasureArtifactResultV1>, ErasureErrorV1> {
    if results.len() > ERASURE_MAX_RECEIPTS {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    results.sort_unstable();
    if results
        .windows(2)
        .any(|pair| pair[0].cmp(&pair[1]) == Ordering::Equal)
    {
        Err(ErasureErrorV1::ScopeInvalid)
    } else {
        Ok(results)
    }
}

fn results(value: &Value) -> Result<Vec<ErasureArtifactResultV1>, ErasureErrorV1> {
    let values = array(value, ERASURE_MAX_RECEIPTS)?;
    let results = values
        .iter()
        .map(ErasureArtifactResultV1::from_value)
        .collect::<Result<Vec<_>, _>>()?;
    if strictly_increasing(&results) {
        Ok(results)
    } else {
        Err(ErasureErrorV1::ScopeInvalid)
    }
}

fn references(value: &Value) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    let values = array(value, ERASURE_MAX_RECEIPTS)?;
    let references = values.iter().map(bytes32).collect::<Result<Vec<_>, _>>()?;
    if strictly_increasing(&references) {
        Ok(references)
    } else {
        Err(ErasureErrorV1::ScopeInvalid)
    }
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
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

fn encode_limited(value: &Value, maximum: usize) -> Result<Vec<u8>, ErasureErrorV1> {
    validate_value(value)?;
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    if bytes.len() > maximum {
        Err(ErasureErrorV1::ScopeInvalid)
    } else {
        Ok(bytes)
    }
}

fn decode_limited(bytes: &[u8], maximum: usize) -> Result<Value, ErasureErrorV1> {
    if bytes.len() > maximum {
        return Err(ErasureErrorV1::ScopeInvalid);
    }
    let mut cursor = Cursor::new(bytes);
    let decoded: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| ErasureErrorV1::InvalidEncoding)?;
    if cursor.position()
        != u64::try_from(bytes.len()).map_err(|_| ErasureErrorV1::InvalidEncoding)?
    {
        return Err(ErasureErrorV1::InvalidEncoding);
    }
    let canonical = encode_limited(&decoded, maximum)?;
    if canonical == bytes {
        Ok(decoded)
    } else {
        Err(ErasureErrorV1::InvalidEncoding)
    }
}

fn validate_value(value: &Value) -> Result<(), ErasureErrorV1> {
    match value {
        Value::Array(values) => values.iter().try_for_each(validate_value),
        Value::Bytes(_) | Value::Text(_) | Value::Integer(_) | Value::Bool(_) | Value::Null => {
            Ok(())
        }
        Value::Map(_) | Value::Tag(_, _) | Value::Float(_) | _ => {
            Err(ErasureErrorV1::InvalidEncoding)
        }
    }
}

fn array(value: &Value, maximum: usize) -> Result<&[Value], ErasureErrorV1> {
    let Value::Array(values) = value else {
        return Err(ErasureErrorV1::InvalidEncoding);
    };
    if values.len() > maximum {
        Err(ErasureErrorV1::ScopeInvalid)
    } else {
        Ok(values)
    }
}
fn exact_array(value: &Value, expected: usize) -> Result<&[Value], ErasureErrorV1> {
    let values = array(value, expected)?;
    if values.len() == expected {
        Ok(values)
    } else {
        Err(ErasureErrorV1::InvalidEncoding)
    }
}
fn string(value: &Value) -> Result<&str, ErasureErrorV1> {
    if let Value::Text(value) = value {
        Ok(value)
    } else {
        Err(ErasureErrorV1::InvalidEncoding)
    }
}
fn unsigned(value: &Value) -> Result<u64, ErasureErrorV1> {
    if let Value::Integer(value) = value {
        u64::try_from(*value).map_err(|_| ErasureErrorV1::InvalidEncoding)
    } else {
        Err(ErasureErrorV1::InvalidEncoding)
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
    if let Value::Bytes(value) = value {
        value
            .as_slice()
            .try_into()
            .map(ErasureReferenceV1::from_digest)
            .map_err(|_| ErasureErrorV1::InvalidEncoding)
    } else {
        Err(ErasureErrorV1::InvalidEncoding)
    }
}
fn optional_bytes32(value: &Value) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes32(value).map(Some)
    }
}
fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn reference(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    fn request(selectors: Vec<ErasureSelectorV1>) -> ErasureRequestV1 {
        match ErasureRequestV1::new(
            reference(1),
            reference(2),
            ErasureScopeV1::PrivateSubjectData,
            selectors,
            reference(3),
            reference(4),
            reference(5),
            9,
            10,
            reference(6),
        ) {
            Ok(request) => request,
            Err(error) => panic!("valid ERQ1 request rejected: {error}"),
        }
    }

    fn result(outcome: ErasureAcknowledgementOutcomeV1) -> ErasureArtifactResultV1 {
        ErasureArtifactResultV1::new(
            1,
            reference(10),
            2,
            reference(11),
            reference(12),
            reference(13),
            outcome,
        )
    }

    #[test]
    fn request_codec_is_deterministic_and_canonicalizes_selector_order() {
        let first = request(vec![
            ErasureSelectorV1::from_digest(reference(8)),
            ErasureSelectorV1::from_digest(reference(7)),
        ]);
        let second = request(vec![
            ErasureSelectorV1::from_digest(reference(7)),
            ErasureSelectorV1::from_digest(reference(8)),
        ]);
        let first_bytes = match first.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("ERQ1 encoding failed: {error}"),
        };
        let second_bytes = match second.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("ERQ1 encoding failed: {error}"),
        };
        assert_eq!(first_bytes, second_bytes);
        let decoded = match ErasureRequestV1::from_canonical_cbor(&first_bytes) {
            Ok(value) => value,
            Err(error) => panic!("ERQ1 decoding failed: {error}"),
        };
        assert_eq!(decoded, first);
    }

    #[test]
    fn request_rejects_empty_duplicate_and_conflicting_scope_bounds() {
        assert_eq!(
            ErasureRequestV1::new(
                reference(1),
                reference(2),
                ErasureScopeV1::PrivateSubjectData,
                Vec::new(),
                reference(3),
                reference(4),
                reference(5),
                9,
                10,
                reference(6)
            ),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::new(
                reference(1),
                reference(2),
                ErasureScopeV1::PrivateSubjectData,
                vec![
                    ErasureSelectorV1::from_digest(reference(7)),
                    ErasureSelectorV1::from_digest(reference(7))
                ],
                reference(3),
                reference(4),
                reference(5),
                9,
                10,
                reference(6)
            ),
            Err(ErasureErrorV1::ScopeInvalid)
        );
        assert_eq!(
            ErasureRequestV1::new(
                reference(1),
                reference(2),
                ErasureScopeV1::PrivateSubjectData,
                vec![ErasureSelectorV1::from_digest(reference(7))],
                reference(3),
                reference(4),
                reference(5),
                11,
                10,
                reference(6)
            ),
            Err(ErasureErrorV1::ScopeInvalid)
        );
    }

    #[test]
    fn codecs_reject_unknown_trailing_map_and_version_fields() {
        let encoded =
            match request(vec![ErasureSelectorV1::from_digest(reference(7))]).to_canonical_cbor() {
                Ok(bytes) => bytes,
                Err(error) => panic!("ERQ1 encoding failed: {error}"),
            };
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&trailing),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let map = Value::Map(vec![(
            Value::Text("request".to_owned()),
            Value::Bytes(vec![0; 32]),
        )]);
        let mut map_bytes = Vec::new();
        let map_write = ciborium::into_writer(&map, &mut map_bytes);
        assert!(map_write.is_ok());
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&map_bytes),
            Err(ErasureErrorV1::InvalidEncoding)
        );
        let unsupported = Value::Array(vec![text(ERQ1), uint(2)]);
        let unsupported_bytes =
            match encode_limited(&unsupported, ERASURE_REQUEST_OR_STATE_MAX_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => panic!("test version encoding failed: {error}"),
            };
        assert_eq!(
            ErasureRequestV1::from_canonical_cbor(&unsupported_bytes),
            Err(ErasureErrorV1::InvalidEncoding)
        );
    }

    #[test]
    fn lifecycle_permits_only_the_adr060_forward_edges() {
        assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Authorized));
        assert!(ErasureLifecycleV1::Submitted.permits(ErasureLifecycleV1::Rejected));
        assert!(ErasureLifecycleV1::AwaitingAcknowledgements.permits(ErasureLifecycleV1::Complete));
        assert!(ErasureLifecycleV1::AwaitingAcknowledgements
            .permits(ErasureLifecycleV1::PartialFailure));
        assert!(!ErasureLifecycleV1::Complete.permits(ErasureLifecycleV1::AwaitingAcknowledgements));
        assert!(!ErasureLifecycleV1::Authorized.permits(ErasureLifecycleV1::DestructionDispatched));
    }

    #[test]
    fn state_requires_freeze_and_cannot_complete_with_pending_owners() {
        let submitted = match ErasureStateV1::submitted(reference(1), reference(2)) {
            Ok(state) => state,
            Err(error) => panic!("submitted state failed: {error}"),
        };
        let authorized = match submitted.transition(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
            ErasureReplayClaimV1::Exact,
            reference(3),
        ) {
            Ok(state) => state,
            Err(error) => panic!("authorization transition failed: {error}"),
        };
        assert_eq!(
            authorized.transition(
                ErasureLifecycleV1::AccessFrozen,
                None,
                Vec::new(),
                Vec::new(),
                ErasureReplayClaimV1::Exact,
                reference(4)
            ),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let frozen = match authorized.transition(
            ErasureLifecycleV1::AccessFrozen,
            Some(11),
            Vec::new(),
            Vec::new(),
            ErasureReplayClaimV1::Exact,
            reference(4),
        ) {
            Ok(state) => state,
            Err(error) => panic!("freeze transition failed: {error}"),
        };
        assert_eq!(
            frozen.transition(
                ErasureLifecycleV1::Complete,
                Some(11),
                vec![reference(9)],
                Vec::new(),
                ErasureReplayClaimV1::StructuralOnly,
                reference(5)
            ),
            Err(ErasureErrorV1::PolicyConflict)
        );
    }

    #[test]
    fn state_codec_refuses_tampered_digest_and_preserves_monotonic_evidence() {
        let submitted = match ErasureStateV1::submitted(reference(1), reference(2)) {
            Ok(state) => state,
            Err(error) => panic!("submitted state failed: {error}"),
        };
        let state = match submitted.transition(
            ErasureLifecycleV1::Authorized,
            None,
            Vec::new(),
            Vec::new(),
            ErasureReplayClaimV1::Exact,
            reference(3),
        ) {
            Ok(state) => state,
            Err(error) => panic!("authorization transition failed: {error}"),
        };
        let bytes = match state.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("ERS1 encoding failed: {error}"),
        };
        assert_eq!(ErasureStateV1::from_canonical_cbor(&bytes), Ok(state));
        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            ErasureStateV1::from_canonical_cbor(&tampered),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[test]
    fn receipt_order_is_independent_of_acknowledgement_arrival() {
        let low = ErasureArtifactResultV1::new(
            1,
            reference(1),
            1,
            reference(2),
            reference(3),
            reference(4),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        );
        let high = ErasureArtifactResultV1::new(
            2,
            reference(1),
            1,
            reference(2),
            reference(3),
            reference(4),
            ErasureAcknowledgementOutcomeV1::Acknowledged,
        );
        let one = match ErasureReceiptV1::new(
            reference(1),
            ErasureLifecycleV1::Complete,
            10,
            vec![high, low],
            vec![result(ErasureAcknowledgementOutcomeV1::Acknowledged)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            reference(5),
            reference(6),
            reference(7),
            11,
            reference(8),
        ) {
            Ok(receipt) => receipt,
            Err(error) => panic!("receipt rejected: {error}"),
        };
        let two = match ErasureReceiptV1::new(
            reference(1),
            ErasureLifecycleV1::Complete,
            10,
            vec![low, high],
            vec![result(ErasureAcknowledgementOutcomeV1::Acknowledged)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            reference(5),
            reference(6),
            reference(7),
            11,
            reference(8),
        ) {
            Ok(receipt) => receipt,
            Err(error) => panic!("receipt rejected: {error}"),
        };
        let one_bytes = match one.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("ERC1 encoding failed: {error}"),
        };
        let two_bytes = match two.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("ERC1 encoding failed: {error}"),
        };
        assert_eq!(one_bytes, two_bytes);
        assert_eq!(ErasureReceiptV1::from_canonical_cbor(&one_bytes), Ok(one));
    }

    #[test]
    fn receipt_requires_complete_positive_evidence_and_partial_failure_for_negative_acknowledgements(
    ) {
        assert_eq!(
            ErasureReceiptV1::new(
                reference(1),
                ErasureLifecycleV1::Complete,
                10,
                vec![result(ErasureAcknowledgementOutcomeV1::Negative)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                reference(5),
                reference(6),
                reference(7),
                11,
                reference(8)
            ),
            Err(ErasureErrorV1::ReplicaNegativeAcknowledgement)
        );
        assert_eq!(
            ErasureReceiptV1::new(
                reference(1),
                ErasureLifecycleV1::PartialFailure,
                10,
                vec![result(ErasureAcknowledgementOutcomeV1::Acknowledged)],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                reference(5),
                reference(6),
                reference(7),
                11,
                reference(8)
            ),
            Err(ErasureErrorV1::PolicyConflict)
        );
        assert!(ErasureReceiptV1::new(
            reference(1),
            ErasureLifecycleV1::PartialFailure,
            10,
            vec![result(ErasureAcknowledgementOutcomeV1::Stale)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            reference(5),
            reference(6),
            reference(7),
            11,
            reference(8)
        )
        .is_ok());
    }

    #[test]
    fn safe_error_codes_are_closed_and_do_not_expose_payload() {
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
}
