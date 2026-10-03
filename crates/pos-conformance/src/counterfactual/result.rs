//! Immutable CFR1 counterfactual results defined by ADR-064.
//!
//! A `CounterfactualResultV1` is the terminal record that the core
//! `CounterfactualCoordinator` emits for one Fork generation after it
//! recomputes, or fails to recompute, the complete endogenous suffix of one
//! `CounterfactualPlanV1`. The record binds the plan and Fork, the committed
//! recomputation range and its checkpoints, the terminal state and safe error,
//! the suffix/dependency/provenance roots, the surviving `ReplayClaim`, and the
//! execution-profile, trust-policy, and evaluator identities.
//!
//! RCP1 checkpoints are bound only by tick, Fork generation, and opaque
//! 32-byte digest, so this contract does not depend on the RCP1 record shape.
//!
//! Contract decisions that ADR-064 leaves open:
//!
//! - The terminal error-code wire table (codes 0 through 32) is normative: the
//!   25 base ADR-064 error codes in ADR order (0 through 24), then the 8
//!   frontier/invalidation amendment codes (25 through 32). Codes are never
//!   reordered or reused; a new code may only be appended in a new version.
//! - A `Completed` result must carry a checkpoint at the horizon Tick, so a
//!   completed result always carries evidence of the final recomputed state.
//!   ADR-064 is silent here; the coordinator (#339) must therefore checkpoint
//!   the horizon Tick before it emits a `Completed` result.
//! - `fork_generation` starts at 1. Generation 0 is the initial generation
//!   before any recomputation: SIV1 suffix invalidation accepts generation 0
//!   only with prior generation 0 and no invalidated artifacts, and every
//!   invalidation advances to the prior generation plus one. A CFR1 result
//!   records a recomputation, so it never names generation 0.
//! - Any terminal error code is accepted under `Failed`; CFR1 does not
//!   restrict which codes may end a recomputation.
//!
//! The largest structurally valid record is far below the 16 MiB bound, which
//! is therefore enforced on untrusted input before any allocation.

use super::codec::{
    bytes_value, decode_canonical, encode_value, text_value, uint_value, CborLimits, FieldReader,
    WireError,
};
use crate::{domain_digest, ReplayClaimV1};
use ciborium::value::Value;
use std::collections::BTreeSet;

/// Magic for the immutable counterfactual-result record.
pub const COUNTERFACTUAL_RESULT_MAGIC_V1: &str = "CFR1";
/// Maximum encoded size of a CFR1 counterfactual result.
pub const MAX_COUNTERFACTUAL_RESULT_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of RCP1 checkpoint references bound by one CFR1 result.
pub const MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1: usize = 65_536;

const FIELD_COUNT: usize = 20;
const CHECKPOINT_FIELD_COUNT: usize = 3;
const TERMINAL_ERROR_FIELD_COUNT: usize = 4;
const LIMITS: CborLimits = CborLimits {
    maximum_bytes: MAX_COUNTERFACTUAL_RESULT_BYTES_V1,
    maximum_depth: 3,
    maximum_items: 65_536,
    allow_simple_values: true,
};
const RESULT_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.CounterfactualResult.v1";
const REPLAY_CLAIMS: [ReplayClaimV1; 5] = [
    ReplayClaimV1::Exact,
    ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    ReplayClaimV1::StructuralOnly,
    ReplayClaimV1::UnverifiableArtifactsMissing,
    ReplayClaimV1::IncompatibleProfile,
];

/// Closed safe errors exposed by the CFR1 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfactualResultContractErrorV1 {
    /// The bytes are malformed, noncanonical, or contain a forbidden CBOR type.
    InvalidEncoding,
    /// The record magic or schema version is not supported.
    UnsupportedVersion,
    /// A value, list, range, or encoded record exceeds its specified bound.
    FieldOutOfBounds,
    /// A closed enum code is not defined by CFR1 version 1.
    UnknownEnum,
    /// Checkpoint references are not in strictly increasing tick order.
    NonCanonicalOrder,
    /// Two checkpoint references bind the same checkpoint digest.
    DuplicateIdentity,
    /// A checkpoint reference names a Fork generation other than the result's.
    MixedForkGeneration,
    /// The terminal state, terminal error, committed range, and checkpoints disagree.
    InconsistentTerminalState,
    /// An incomplete suffix claims an exact replay outcome.
    IncompleteSuffixClaim,
    /// The content does not match its declared result digest.
    DigestMismatch,
}

impl std::fmt::Display for CounterfactualResultContractErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid CFR1 counterfactual result encoding",
            Self::UnsupportedVersion => "unsupported CFR1 counterfactual result version",
            Self::FieldOutOfBounds => "CFR1 counterfactual result field is out of bounds",
            Self::UnknownEnum => "CFR1 counterfactual result enum code is unknown",
            Self::NonCanonicalOrder => "CFR1 counterfactual result checkpoints are not canonical",
            Self::DuplicateIdentity => "CFR1 counterfactual result checkpoint is duplicated",
            Self::MixedForkGeneration => "CFR1 counterfactual result mixes Fork generations",
            Self::InconsistentTerminalState => {
                "CFR1 counterfactual result terminal state is inconsistent"
            }
            Self::IncompleteSuffixClaim => {
                "CFR1 counterfactual result claims exact success for an incomplete suffix"
            }
            Self::DigestMismatch => "CFR1 counterfactual result digest does not match",
        })
    }
}

impl std::error::Error for CounterfactualResultContractErrorV1 {}

/// How the recomputation of the endogenous suffix ended.
///
/// The discriminant is the exact CFR1 wire code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum CounterfactualTerminalStateV1 {
    /// Every Tick through the horizon committed under the result generation.
    ///
    /// The last checkpoint must be at the horizon Tick, so a completed result
    /// always carries evidence of its final state.
    Completed = 0,
    /// A typed failure stopped recomputation; the suffix remains incomplete.
    Failed = 1,
    /// A non-authoritative safe-stop ended recomputation; the suffix remains incomplete.
    SafeStopped = 2,
}

impl CounterfactualTerminalStateV1 {
    /// Every terminal state, indexed by its CFR1 wire code.
    pub const ALL: [Self; 3] = [Self::Completed, Self::Failed, Self::SafeStopped];
}

/// The closed ADR-064 error code that ended a failed recomputation.
///
/// The discriminant is the exact CFR1 wire code and this table is the
/// normative wire mapping: the 25 base ADR-064 error codes in ADR order
/// (0 through 24), followed by the 8 frontier/invalidation amendment codes
/// (25 through 32). It must never be reordered; any code is accepted under
/// [`CounterfactualTerminalStateV1::Failed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum CounterfactualTerminalErrorCodeV1 {
    InvalidEncoding = 0,
    UnsupportedVersion = 1,
    FieldOutOfBounds = 2,
    UnknownEnum = 3,
    NonCanonicalOrder = 4,
    DuplicateIdentity = 5,
    ParentCutNotFound = 6,
    InterventionBeforeCut = 7,
    InterventionConflict = 8,
    NonContiguousOrdinal = 9,
    TargetNotIntervenable = 10,
    UnauthorizedIntervention = 11,
    ConsentInvalid = 12,
    UnclassifiedInput = 13,
    FrozenArtifactMissing = 14,
    FrozenArtifactDigestMismatch = 15,
    UnclosedEndogenousInput = 16,
    IncompatibleExecutionProfile = 17,
    PluginCompositionMismatch = 18,
    SchemaUnsupported = 19,
    ResourceLimitExceeded = 20,
    PluginFailure = 21,
    AtomicCommitFailed = 22,
    ReplayClaimInsufficient = 23,
    ProvenanceMissing = 24,
    DependencyGraphIncomplete = 25,
    UnknownDependencyEdge = 26,
    FrontierOutOfRange = 27,
    FrontierOrderInvalid = 28,
    InvalidationConflict = 29,
    PriorGenerationMismatch = 30,
    InvalidArtifactReuse = 31,
    MixedForkGeneration = 32,
}

impl CounterfactualTerminalErrorCodeV1 {
    /// Every terminal error code, indexed by its CFR1 wire code.
    pub const ALL: [Self; 33] = [
        Self::InvalidEncoding,
        Self::UnsupportedVersion,
        Self::FieldOutOfBounds,
        Self::UnknownEnum,
        Self::NonCanonicalOrder,
        Self::DuplicateIdentity,
        Self::ParentCutNotFound,
        Self::InterventionBeforeCut,
        Self::InterventionConflict,
        Self::NonContiguousOrdinal,
        Self::TargetNotIntervenable,
        Self::UnauthorizedIntervention,
        Self::ConsentInvalid,
        Self::UnclassifiedInput,
        Self::FrozenArtifactMissing,
        Self::FrozenArtifactDigestMismatch,
        Self::UnclosedEndogenousInput,
        Self::IncompatibleExecutionProfile,
        Self::PluginCompositionMismatch,
        Self::SchemaUnsupported,
        Self::ResourceLimitExceeded,
        Self::PluginFailure,
        Self::AtomicCommitFailed,
        Self::ReplayClaimInsufficient,
        Self::ProvenanceMissing,
        Self::DependencyGraphIncomplete,
        Self::UnknownDependencyEdge,
        Self::FrontierOutOfRange,
        Self::FrontierOrderInvalid,
        Self::InvalidationConflict,
        Self::PriorGenerationMismatch,
        Self::InvalidArtifactReuse,
        Self::MixedForkGeneration,
    ];
}

/// The safe terminal error of a failed recomputation.
///
/// It exposes only the closed code, the first canonical coordinate, and an
/// optional safe digest; the CFR1 wire form is
/// `[code, tick, scheduler_position, safe_digest_or_null]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualTerminalErrorV1 {
    /// Closed ADR-064 error code.
    pub code: CounterfactualTerminalErrorCodeV1,
    /// The first uncommitted Tick, where the failure was detected.
    pub tick: u64,
    /// Scheduler position of the first failing coordinate within that Tick.
    pub scheduler_position: u32,
    /// Optional digest that is safe to disclose for the failing coordinate.
    pub safe_digest: Option<[u8; 32]>,
}

/// One RCP1 recompute checkpoint bound by digest.
///
/// The CFR1 wire form is `[tick, fork_generation, checkpoint_digest]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualCheckpointRefV1 {
    /// Tick Boundary at which the checkpoint was taken.
    pub tick: u64,
    /// Fork generation the checkpoint belongs to.
    pub fork_generation: u64,
    /// Digest of the complete canonical RCP1 checkpoint record.
    pub checkpoint_digest: [u8; 32],
}

/// Complete immutable counterfactual result represented by a CFR1 record.
///
/// The exact deterministic-CBOR array has 20 fields in declaration order,
/// preceded by the `CFR1` magic and version `1`. The result digest covers
/// fields 0 through 18 under the `PiglorOS.CounterfactualResult.v1\0` domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterfactualResultV1 {
    /// Result identifier.
    pub result_id: [u8; 16],
    /// Digest of the `CounterfactualPlanV1` that was recomputed.
    pub plan_digest: [u8; 32],
    /// Fork identifier.
    pub fork_id: [u8; 16],
    /// Fork generation every recomputed Tick and checkpoint belongs to.
    ///
    /// It starts at 1; generation 0 is the initial generation before any
    /// recomputation and is rejected as out of bounds.
    pub fork_generation: u64,
    /// First recomputation Tick of the plan.
    pub first_tick: u64,
    /// Inclusive horizon Tick of the plan.
    pub horizon_tick: u64,
    /// Last Tick committed under this generation, or `None` when none committed.
    pub committed_through_tick: Option<u64>,
    /// RCP1 checkpoints in strictly increasing tick order.
    pub checkpoints: Vec<CounterfactualCheckpointRefV1>,
    /// How recomputation ended.
    pub terminal_state: CounterfactualTerminalStateV1,
    /// Safe terminal error, present exactly for a failed recomputation.
    pub terminal_error: Option<CounterfactualTerminalErrorV1>,
    /// Digest of the committed recomputed suffix.
    pub suffix_digest: [u8; 32],
    /// Root of every used and generated dependency edge.
    pub dependency_root: [u8; 32],
    /// Root of the PROV evidence for every generated output.
    pub provenance_root: [u8; 32],
    /// The replay claim that survives the evidence and erasure state.
    pub replay_claim: ReplayClaimV1,
    /// Digest of the EPF1 execution profile.
    pub execution_profile_digest: [u8; 32],
    /// Digest of the TPS1 trust-policy snapshot.
    pub trust_policy_snapshot_digest: [u8; 32],
    /// Digest of the evaluator identity that produced this result.
    pub evaluator_identity_digest: [u8; 32],
    /// Domain-separated digest over fields 0 through 18.
    pub result_digest: [u8; 32],
}

impl CounterfactualResultV1 {
    /// Whether every Tick through the horizon committed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.committed_through_tick, Some(tick) if tick == self.horizon_tick)
    }

    /// Validate CFR1 bounds, checkpoint order, generation consistency,
    /// terminal-state consistency, the replay claim, and the result digest.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when any field, ordering, or digest is invalid.
    pub fn validate(&self) -> Result<(), CounterfactualResultContractErrorV1> {
        validated_body_fields(self).map(drop)
    }

    /// Encode this result as an exact deterministic-CBOR CFR1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CounterfactualResultContractErrorV1> {
        validated_body_fields(self).and_then(|mut fields| {
            fields.push(bytes_value(&self.result_digest));
            encode_value(&fields).map_err(contract_error)
        })
    }

    /// Decode and validate exact canonical CFR1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// structurally invalid CFR1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CounterfactualResultContractErrorV1> {
        decode_canonical(bytes, LIMITS)
            .map_err(contract_error)
            .and_then(|value| decode_result(&value))
            .and_then(|result| result.validate().map(|()| result))
    }

    /// Compute the CFR1 domain-separated digest over fields 0 through 18.
    ///
    /// The digest is computed over the fields as they are, without validating
    /// them, so a caller can seal a result before validating it.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when the fields cannot be encoded.
    pub fn digest(&self) -> Result<[u8; 32], CounterfactualResultContractErrorV1> {
        digested_body_fields(self).map(|(_, digest)| digest)
    }
}

/// Validate every CFR1 rule and return the unsigned body fields 0 through 18,
/// so encoding reuses the field list that the digest check already built.
fn validated_body_fields(
    result: &CounterfactualResultV1,
) -> Result<Vec<Value>, CounterfactualResultContractErrorV1> {
    validate_range(result)
        .and_then(|()| validate_checkpoints(result))
        .and_then(|()| validate_terminal_state(result))
        .and_then(|()| validate_replay_claim(result))
        .and_then(|()| digested_body_fields(result))
        .and_then(|(fields, digest)| {
            if digest == result.result_digest {
                Ok(fields)
            } else {
                Err(CounterfactualResultContractErrorV1::DigestMismatch)
            }
        })
}

/// Build the unsigned body fields 0 through 18 once and digest their
/// deterministic-CBOR array encoding under the CFR1 domain.
fn digested_body_fields(
    result: &CounterfactualResultV1,
) -> Result<(Vec<Value>, [u8; 32]), CounterfactualResultContractErrorV1> {
    let fields = body_fields(result);
    encode_value(&fields)
        .map_err(contract_error)
        .map(|unsigned| {
            let digest = domain_digest(RESULT_DIGEST_DOMAIN_V1, &unsigned);
            (fields, digest)
        })
}

fn validate_range(
    result: &CounterfactualResultV1,
) -> Result<(), CounterfactualResultContractErrorV1> {
    let committed_in_range = result
        .committed_through_tick
        .is_none_or(|tick| (result.first_tick..=result.horizon_tick).contains(&tick));
    if result.fork_generation == 0
        || result.horizon_tick < result.first_tick
        || !committed_in_range
        || result.checkpoints.len() > MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1
    {
        Err(CounterfactualResultContractErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_checkpoints(
    result: &CounterfactualResultV1,
) -> Result<(), CounterfactualResultContractErrorV1> {
    let checkpoints = &result.checkpoints;
    let outside_committed_range = checkpoints.iter().any(|checkpoint| {
        result
            .committed_through_tick
            .is_none_or(|last| checkpoint.tick < result.first_tick || checkpoint.tick > last)
    });
    if outside_committed_range {
        Err(CounterfactualResultContractErrorV1::FieldOutOfBounds)
    } else if checkpoints
        .iter()
        .any(|checkpoint| checkpoint.fork_generation != result.fork_generation)
    {
        Err(CounterfactualResultContractErrorV1::MixedForkGeneration)
    } else if checkpoints
        .windows(2)
        .any(|pair| pair[0].tick >= pair[1].tick)
    {
        Err(CounterfactualResultContractErrorV1::NonCanonicalOrder)
    } else if checkpoints
        .iter()
        .map(|checkpoint| checkpoint.checkpoint_digest)
        .collect::<BTreeSet<_>>()
        .len()
        == checkpoints.len()
    {
        Ok(())
    } else {
        Err(CounterfactualResultContractErrorV1::DuplicateIdentity)
    }
}

fn validate_terminal_state(
    result: &CounterfactualResultV1,
) -> Result<(), CounterfactualResultContractErrorV1> {
    let consistent = match result.terminal_state {
        CounterfactualTerminalStateV1::Completed => {
            result.is_complete()
                && result.terminal_error.is_none()
                && result
                    .checkpoints
                    .last()
                    .is_some_and(|checkpoint| checkpoint.tick == result.horizon_tick)
        }
        CounterfactualTerminalStateV1::Failed => {
            !result.is_complete()
                && result.terminal_error.as_ref().is_some_and(|error| {
                    error.tick
                        == result
                            .committed_through_tick
                            .map_or(result.first_tick, |tick| tick + 1)
                })
        }
        CounterfactualTerminalStateV1::SafeStopped => {
            !result.is_complete() && result.terminal_error.is_none()
        }
    };
    if consistent {
        Ok(())
    } else {
        Err(CounterfactualResultContractErrorV1::InconsistentTerminalState)
    }
}

const fn validate_replay_claim(
    result: &CounterfactualResultV1,
) -> Result<(), CounterfactualResultContractErrorV1> {
    let exact = matches!(
        result.replay_claim,
        ReplayClaimV1::Exact | ReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    if exact && !result.is_complete() {
        Err(CounterfactualResultContractErrorV1::IncompleteSuffixClaim)
    } else {
        Ok(())
    }
}

fn body_fields(result: &CounterfactualResultV1) -> Vec<Value> {
    vec![
        text_value(COUNTERFACTUAL_RESULT_MAGIC_V1),
        uint_value(1),
        bytes_value(&result.result_id),
        bytes_value(&result.plan_digest),
        bytes_value(&result.fork_id),
        uint_value(result.fork_generation),
        uint_value(result.first_tick),
        uint_value(result.horizon_tick),
        result
            .committed_through_tick
            .map_or(Value::Null, uint_value),
        Value::Array(result.checkpoints.iter().map(encode_checkpoint).collect()),
        uint_value(u64::from(result.terminal_state as u8)),
        result
            .terminal_error
            .as_ref()
            .map_or(Value::Null, encode_terminal_error),
        bytes_value(&result.suffix_digest),
        bytes_value(&result.dependency_root),
        bytes_value(&result.provenance_root),
        uint_value(replay_claim_code(result.replay_claim)),
        bytes_value(&result.execution_profile_digest),
        bytes_value(&result.trust_policy_snapshot_digest),
        bytes_value(&result.evaluator_identity_digest),
    ]
}

fn encode_checkpoint(checkpoint: &CounterfactualCheckpointRefV1) -> Value {
    Value::Array(vec![
        uint_value(checkpoint.tick),
        uint_value(checkpoint.fork_generation),
        bytes_value(&checkpoint.checkpoint_digest),
    ])
}

fn encode_terminal_error(error: &CounterfactualTerminalErrorV1) -> Value {
    Value::Array(vec![
        uint_value(u64::from(error.code as u8)),
        uint_value(error.tick),
        uint_value(u64::from(error.scheduler_position)),
        error
            .safe_digest
            .map_or(Value::Null, |digest| bytes_value(&digest)),
    ])
}

const fn replay_claim_code(claim: ReplayClaimV1) -> u64 {
    match claim {
        ReplayClaimV1::Exact => 0,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews => 1,
        ReplayClaimV1::StructuralOnly => 2,
        ReplayClaimV1::UnverifiableArtifactsMissing => 3,
        ReplayClaimV1::IncompatibleProfile => 4,
    }
}

fn decode_result(
    value: &Value,
) -> Result<CounterfactualResultV1, CounterfactualResultContractErrorV1> {
    let mut fields =
        FieldReader::with_header(value, FIELD_COUNT, COUNTERFACTUAL_RESULT_MAGIC_V1, 1);
    let result_id = fields.read_bytes::<16>();
    let plan_digest = fields.read_bytes::<32>();
    let fork_id = fields.read_bytes::<16>();
    let fork_generation = fields.read_u64();
    let first_tick = fields.read_u64();
    let horizon_tick = fields.read_u64();
    let committed_through_tick = fields.read_optional_u64();
    let checkpoints = fields.read_array(checkpoint_field);
    let terminal_state = fields.read_enum(
        &CounterfactualTerminalStateV1::ALL,
        CounterfactualTerminalStateV1::Completed,
    );
    let terminal_error = fields.read_optional(terminal_error_field);
    let suffix_digest = fields.read_bytes::<32>();
    let dependency_root = fields.read_bytes::<32>();
    let provenance_root = fields.read_bytes::<32>();
    let replay_claim = fields.read_enum(&REPLAY_CLAIMS, ReplayClaimV1::Exact);
    let execution_profile_digest = fields.read_bytes::<32>();
    let trust_policy_snapshot_digest = fields.read_bytes::<32>();
    let evaluator_identity_digest = fields.read_bytes::<32>();
    let result_digest = fields.read_bytes::<32>();
    fields
        .finish()
        .map(|()| CounterfactualResultV1 {
            result_id,
            plan_digest,
            fork_id,
            fork_generation,
            first_tick,
            horizon_tick,
            committed_through_tick,
            checkpoints,
            terminal_state,
            terminal_error,
            suffix_digest,
            dependency_root,
            provenance_root,
            replay_claim,
            execution_profile_digest,
            trust_policy_snapshot_digest,
            evaluator_identity_digest,
            result_digest,
        })
        .map_err(contract_error)
}

fn checkpoint_field(value: &Value) -> Result<CounterfactualCheckpointRefV1, WireError> {
    let mut fields = FieldReader::new(value, CHECKPOINT_FIELD_COUNT);
    let tick = fields.read_u64();
    let fork_generation = fields.read_u64();
    let checkpoint_digest = fields.read_bytes::<32>();
    fields.finish().map(|()| CounterfactualCheckpointRefV1 {
        tick,
        fork_generation,
        checkpoint_digest,
    })
}

fn terminal_error_field(value: &Value) -> Result<CounterfactualTerminalErrorV1, WireError> {
    let mut fields = FieldReader::new(value, TERMINAL_ERROR_FIELD_COUNT);
    let code = fields.read_enum(
        &CounterfactualTerminalErrorCodeV1::ALL,
        CounterfactualTerminalErrorCodeV1::InvalidEncoding,
    );
    let tick = fields.read_u64();
    let scheduler_position = fields.read_u32();
    let safe_digest = fields.read_optional_bytes::<32>();
    fields.finish().map(|()| CounterfactualTerminalErrorV1 {
        code,
        tick,
        scheduler_position,
        safe_digest,
    })
}

const fn contract_error(error: WireError) -> CounterfactualResultContractErrorV1 {
    match error {
        WireError::InvalidEncoding => CounterfactualResultContractErrorV1::InvalidEncoding,
        WireError::FieldOutOfBounds => CounterfactualResultContractErrorV1::FieldOutOfBounds,
        WireError::UnsupportedVersion => CounterfactualResultContractErrorV1::UnsupportedVersion,
        WireError::UnknownEnum => CounterfactualResultContractErrorV1::UnknownEnum,
    }
}
