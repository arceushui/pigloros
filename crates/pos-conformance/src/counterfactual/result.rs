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
//! The largest structurally valid record is far below the 16 MiB bound, which
//! is therefore enforced on untrusted input before any allocation.

use crate::{domain_digest, ReplayClaimV1};
use ciborium::value::Value;
use std::collections::BTreeSet;
use std::io::Cursor;

/// Magic for the immutable counterfactual-result record.
pub const COUNTERFACTUAL_RESULT_MAGIC_V1: &str = "CFR1";
/// Maximum encoded size of a CFR1 counterfactual result.
pub const MAX_COUNTERFACTUAL_RESULT_BYTES_V1: usize = 16 * 1024 * 1024;
/// Maximum number of RCP1 checkpoint references bound by one CFR1 result.
pub const MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1: usize = 65_536;

const FIELD_COUNT: usize = 20;
const CHECKPOINT_FIELD_COUNT: usize = 3;
const TERMINAL_ERROR_FIELD_COUNT: usize = 4;
const MAX_NESTING_DEPTH: u8 = 3;
const MAX_NESTED_ARRAY_ITEMS: u64 = 65_536;
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
/// The discriminant is the exact CFR1 wire code: the base ADR-064 error set
/// in declaration order, followed by the frontier/invalidation amendment.
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
        validate_range(self)
            .and_then(|()| validate_checkpoints(self))
            .and_then(|()| validate_terminal_state(self))
            .and_then(|()| validate_replay_claim(self))
            .and_then(|()| validate_digest(self))
    }

    /// Encode this result as an exact deterministic-CBOR CFR1 array.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error when validation fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, CounterfactualResultContractErrorV1> {
        self.validate().map(|()| {
            let mut fields = result_fields(self);
            fields.push(byte_string(&self.result_digest));
            encode_value(&Value::Array(fields))
        })
    }

    /// Decode and validate exact canonical CFR1 bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed safe error for malformed, noncanonical, oversized, or
    /// structurally invalid CFR1 records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, CounterfactualResultContractErrorV1> {
        if bytes.len() > MAX_COUNTERFACTUAL_RESULT_BYTES_V1 {
            return Err(CounterfactualResultContractErrorV1::FieldOutOfBounds);
        }
        let result = decode_value(bytes).and_then(|value| decode_result(&value))?;
        result.validate().map(|()| result)
    }

    /// Compute the CFR1 domain-separated digest over fields 0 through 18.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        domain_digest(
            RESULT_DIGEST_DOMAIN_V1,
            &encode_value(&Value::Array(result_fields(self))),
        )
    }
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

fn validate_digest(
    result: &CounterfactualResultV1,
) -> Result<(), CounterfactualResultContractErrorV1> {
    if result.digest() == result.result_digest {
        Ok(())
    } else {
        Err(CounterfactualResultContractErrorV1::DigestMismatch)
    }
}

fn result_fields(result: &CounterfactualResultV1) -> Vec<Value> {
    vec![
        Value::Text(COUNTERFACTUAL_RESULT_MAGIC_V1.to_owned()),
        uint(1),
        byte_string(&result.result_id),
        byte_string(&result.plan_digest),
        byte_string(&result.fork_id),
        uint(result.fork_generation),
        uint(result.first_tick),
        uint(result.horizon_tick),
        result.committed_through_tick.map_or(Value::Null, uint),
        Value::Array(result.checkpoints.iter().map(encode_checkpoint).collect()),
        uint(u64::from(result.terminal_state as u8)),
        result
            .terminal_error
            .as_ref()
            .map_or(Value::Null, encode_terminal_error),
        byte_string(&result.suffix_digest),
        byte_string(&result.dependency_root),
        byte_string(&result.provenance_root),
        uint(replay_claim_code(result.replay_claim)),
        byte_string(&result.execution_profile_digest),
        byte_string(&result.trust_policy_snapshot_digest),
        byte_string(&result.evaluator_identity_digest),
    ]
}

fn encode_checkpoint(checkpoint: &CounterfactualCheckpointRefV1) -> Value {
    Value::Array(vec![
        uint(checkpoint.tick),
        uint(checkpoint.fork_generation),
        byte_string(&checkpoint.checkpoint_digest),
    ])
}

fn encode_terminal_error(error: &CounterfactualTerminalErrorV1) -> Value {
    Value::Array(vec![
        uint(u64::from(error.code as u8)),
        uint(error.tick),
        uint(u64::from(error.scheduler_position)),
        error
            .safe_digest
            .as_ref()
            .map_or(Value::Null, byte_string::<32>),
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

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn byte_string<const LENGTH: usize>(value: &[u8; LENGTH]) -> Value {
    Value::Bytes(value.to_vec())
}

fn decode_result(
    value: &Value,
) -> Result<CounterfactualResultV1, CounterfactualResultContractErrorV1> {
    let fields = array(value, FIELD_COUNT)?;
    if !matches!(&fields[0], Value::Text(magic) if magic == COUNTERFACTUAL_RESULT_MAGIC_V1)
        || uint_value(&fields[1]) != Ok(1)
    {
        return Err(CounterfactualResultContractErrorV1::UnsupportedVersion);
    }
    Ok(CounterfactualResultV1 {
        result_id: fixed_bytes(&fields[2])?,
        plan_digest: fixed_bytes(&fields[3])?,
        fork_id: fixed_bytes(&fields[4])?,
        fork_generation: uint_value(&fields[5])?,
        first_tick: uint_value(&fields[6])?,
        horizon_tick: uint_value(&fields[7])?,
        committed_through_tick: optional(&fields[8], uint_value)?,
        checkpoints: array_values(&fields[9])?
            .iter()
            .map(decode_checkpoint)
            .collect::<Result<_, _>>()?,
        terminal_state: enum_value(&fields[10], &CounterfactualTerminalStateV1::ALL)?,
        terminal_error: optional(&fields[11], decode_terminal_error)?,
        suffix_digest: fixed_bytes(&fields[12])?,
        dependency_root: fixed_bytes(&fields[13])?,
        provenance_root: fixed_bytes(&fields[14])?,
        replay_claim: enum_value(&fields[15], &REPLAY_CLAIMS)?,
        execution_profile_digest: fixed_bytes(&fields[16])?,
        trust_policy_snapshot_digest: fixed_bytes(&fields[17])?,
        evaluator_identity_digest: fixed_bytes(&fields[18])?,
        result_digest: fixed_bytes(&fields[19])?,
    })
}

fn decode_checkpoint(
    value: &Value,
) -> Result<CounterfactualCheckpointRefV1, CounterfactualResultContractErrorV1> {
    let fields = array(value, CHECKPOINT_FIELD_COUNT)?;
    Ok(CounterfactualCheckpointRefV1 {
        tick: uint_value(&fields[0])?,
        fork_generation: uint_value(&fields[1])?,
        checkpoint_digest: fixed_bytes(&fields[2])?,
    })
}

fn decode_terminal_error(
    value: &Value,
) -> Result<CounterfactualTerminalErrorV1, CounterfactualResultContractErrorV1> {
    let fields = array(value, TERMINAL_ERROR_FIELD_COUNT)?;
    Ok(CounterfactualTerminalErrorV1 {
        code: enum_value(&fields[0], &CounterfactualTerminalErrorCodeV1::ALL)?,
        tick: uint_value(&fields[1])?,
        scheduler_position: uint_value(&fields[2]).and_then(|position| {
            u32::try_from(position)
                .map_err(|_| CounterfactualResultContractErrorV1::FieldOutOfBounds)
        })?,
        safe_digest: optional(&fields[3], fixed_bytes::<32>)?,
    })
}

fn decode_value(bytes: &[u8]) -> Result<Value, CounterfactualResultContractErrorV1> {
    crate::preflight_array_cbor(bytes, MAX_NESTING_DEPTH, MAX_NESTED_ARRAY_ITEMS, true)
        .map_err(preflight_error)?;
    let value: Value = ciborium::from_reader(Cursor::new(bytes))
        .map_err(|_| CounterfactualResultContractErrorV1::InvalidEncoding)?;
    if encode_value(&value) == bytes {
        Ok(value)
    } else {
        Err(CounterfactualResultContractErrorV1::InvalidEncoding)
    }
}

const fn preflight_error(error: crate::CborPreflightError) -> CounterfactualResultContractErrorV1 {
    match error {
        crate::CborPreflightError::InvalidEncoding => {
            CounterfactualResultContractErrorV1::InvalidEncoding
        }
        crate::CborPreflightError::FieldOutOfBounds => {
            CounterfactualResultContractErrorV1::FieldOutOfBounds
        }
    }
}

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).unwrap_or_else(|_| std::process::abort());
    encoded
}

fn array(value: &Value, length: usize) -> Result<&[Value], CounterfactualResultContractErrorV1> {
    match value {
        Value::Array(values) if values.len() == length => Ok(values),
        _ => Err(CounterfactualResultContractErrorV1::InvalidEncoding),
    }
}

fn array_values(value: &Value) -> Result<&[Value], CounterfactualResultContractErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(CounterfactualResultContractErrorV1::InvalidEncoding),
    }
}

fn uint_value(value: &Value) -> Result<u64, CounterfactualResultContractErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| CounterfactualResultContractErrorV1::InvalidEncoding)
        }
        _ => Err(CounterfactualResultContractErrorV1::InvalidEncoding),
    }
}

fn fixed_bytes<const LENGTH: usize>(
    value: &Value,
) -> Result<[u8; LENGTH], CounterfactualResultContractErrorV1> {
    match value {
        Value::Bytes(value) => value
            .as_slice()
            .try_into()
            .map_err(|_| CounterfactualResultContractErrorV1::InvalidEncoding),
        _ => Err(CounterfactualResultContractErrorV1::InvalidEncoding),
    }
}

fn optional<T>(
    value: &Value,
    decode: impl Fn(&Value) -> Result<T, CounterfactualResultContractErrorV1>,
) -> Result<Option<T>, CounterfactualResultContractErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        decode(value).map(Some)
    }
}

fn enum_value<T: Copy>(
    value: &Value,
    codes: &[T],
) -> Result<T, CounterfactualResultContractErrorV1> {
    uint_value(value).and_then(|code| {
        usize::try_from(code)
            .ok()
            .and_then(|index| codes.get(index).copied())
            .ok_or(CounterfactualResultContractErrorV1::UnknownEnum)
    })
}
