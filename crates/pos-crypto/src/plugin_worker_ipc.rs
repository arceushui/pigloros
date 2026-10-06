//! Community Plugin worker IPC envelopes (ADR-061 revision 4, decision 4).
//!
//! The supervisor sends one request envelope to a fresh worker subprocess and
//! reads back one response envelope. Both are canonical CBOR arrays read with
//! the strict reader shared with PMF1, PTR1 and PRV1: definite lengths,
//! shortest-form heads, no maps, tags or floats, and no trailing bytes. A
//! value has exactly one accepted encoding, so a decoded envelope re-encodes
//! to the same bytes.
//!
//! Any envelope fault is the single closed [`WorkerEnvelopeErrorV1`]. The
//! supervisor reports it as the operational `WorkerCrashed`; nothing is
//! fabricated from a faulty envelope. The guest payload inside a well-formed
//! response is opaque here, and its validation belongs to the host.
//!
//! The request is `["PWQ1", 1, export, component, negotiation, limits,
//! simulation_time, invocation]`, where `negotiation` is `[world, abi_major,
//! abi_minor, [required_feature...], pmf1_digest, release_digest]` and
//! `limits` lists the eight `DeterministicBudgetV1` members in PMF1 order.
//!
//! The response is `["PWR1", 1, outcome]`, where `outcome` is one of:
//! - `[0, payload, startup_fuel, call_fuel, memory_bytes]` for a completed
//!   call;
//! - `[1, failure]` for a closed in-worker failure;
//! - `[2, trap_class]` for a trap with a canonical trap class.

use crate::plugin_execution::DeterministicBudgetV1;
use crate::strict_cbor::{Reader, StrictCborError};

/// Magic text of a worker request envelope.
pub const WORKER_REQUEST_MAGIC_V1: &str = "PWQ1";
/// Magic text of a worker response envelope.
pub const WORKER_RESPONSE_MAGIC_V1: &str = "PWR1";
/// Largest Component the request carries: the 32 MiB PMF1 V1 field 9 bound.
pub const MAX_WORKER_COMPONENT_BYTES_V1: usize = 33_554_432;
/// Largest canonical invocation record the request carries.
///
/// It covers the 1 MiB observation, 1 MiB of prior state and 64 KiB for
/// every other `plugin-invocation` field.
pub const MAX_WORKER_INVOCATION_BYTES_V1: usize = 2 * 1_048_576 + 65_536;

const VERSION: u64 = 1;
const REQUEST_FIELDS: u64 = 8;
const RESPONSE_FIELDS: u64 = 3;
const NEGOTIATION_FIELDS: u64 = 6;
const LIMIT_FIELDS: u64 = 8;
const MAX_TEXT_BYTES: usize = 128;
const MAX_FEATURES: usize = 256;
const COMPLETED: u64 = 0;
const FAILED: u64 = 1;
const TRAPPED: u64 = 2;

/// A malformed, non-canonical, truncated or out-of-bounds worker envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("malformed community Plugin worker envelope")]
pub struct WorkerEnvelopeErrorV1;

impl StrictCborError for WorkerEnvelopeErrorV1 {
    fn invalid_encoding(_ordinal: u8) -> Self {
        Self
    }

    fn bounds_exceeded(_ordinal: u8) -> Self {
        Self
    }
}

type EnvelopeReader<'a> = Reader<'a, WorkerEnvelopeErrorV1>;

/// The `guest-v1` export one worker invokes.
///
/// `migrate-state` has no code: a V1 host never invokes it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkerExportV1 {
    /// `describe`.
    Describe,
    /// `reduce`.
    Reduce,
    /// `drive`.
    Drive,
}

impl WorkerExportV1 {
    /// Every export in declaration order; a variant's wire code is its index.
    pub const ALL: [Self; 3] = [Self::Describe, Self::Reduce, Self::Drive];
}

/// The negotiated release tuple the worker checks `describe` against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerNegotiationV1 {
    /// The exact Component world, at most 128 bytes.
    pub world: String,
    /// The negotiated ABI major.
    pub abi_major: u16,
    /// The negotiated ABI minor.
    pub abi_minor: u16,
    /// The required feature IDs: at most 256, each at most 128 bytes.
    pub required_features: Vec<String>,
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// The PMF1 release digest.
    pub release_digest: [u8; 32],
}

/// One invocation request from the supervisor to a fresh worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRequestV1 {
    /// The export to invoke.
    pub export: WorkerExportV1,
    /// The verified Component bytes.
    pub component: Vec<u8>,
    /// The negotiated release tuple.
    pub negotiation: WorkerNegotiationV1,
    /// The effective limits fixed at negotiation.
    pub limits: DeterministicBudgetV1,
    /// Simulation Time that `simulation-time` returns.
    pub simulation_time: u64,
    /// The canonical `plugin-invocation` record; empty for `describe`.
    pub invocation: Vec<u8>,
}

/// A closed failure the in-worker engine reports instead of a result.
///
/// Each variant names the closed host error it reports.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkerFailureV1 {
    /// `InvalidInvocation`.
    InvalidInvocation,
    /// `IncompatibleAbi`: the Component does not implement the world.
    IncompatibleAbi,
    /// `InvalidGuestOutput`.
    InvalidGuestOutput,
    /// `FuelExhausted`.
    FuelExhausted,
    /// `MemoryLimitExceeded`.
    MemoryLimitExceeded,
    /// `HostCallLimitExceeded`.
    HostCallLimitExceeded,
    /// `OutputLimitExceeded`.
    OutputLimitExceeded,
    /// `OperationalWatchdogStop`: the in-worker epoch deadline elapsed.
    OperationalWatchdogStop,
}

impl WorkerFailureV1 {
    /// Every failure in declaration order; a variant's wire code is its index.
    pub const ALL: [Self; 8] = [
        Self::InvalidInvocation,
        Self::IncompatibleAbi,
        Self::InvalidGuestOutput,
        Self::FuelExhausted,
        Self::MemoryLimitExceeded,
        Self::HostCallLimitExceeded,
        Self::OutputLimitExceeded,
        Self::OperationalWatchdogStop,
    ];
}

/// The wire form of one canonical trap class (revision 4 decision 6).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WorkerTrapClassV1 {
    /// `unreachable`.
    Unreachable,
    /// `memory-out-of-bounds`.
    MemoryOutOfBounds,
    /// `table-out-of-bounds`.
    TableOutOfBounds,
    /// `indirect-call`.
    IndirectCall,
    /// `integer-arithmetic`.
    IntegerArithmetic,
    /// `stack-exhausted`.
    StackExhausted,
    /// `other`.
    Other,
}

impl WorkerTrapClassV1 {
    /// Every class in declaration order; a variant's wire code is its index.
    pub const ALL: [Self; 7] = [
        Self::Unreachable,
        Self::MemoryOutOfBounds,
        Self::TableOutOfBounds,
        Self::IndirectCall,
        Self::IntegerArithmetic,
        Self::StackExhausted,
        Self::Other,
    ];
}

/// The lifted guest result and the measured budget of a completed call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerCompletionV1 {
    /// The canonical guest return value, not yet validated by the host.
    pub payload: Vec<u8>,
    /// Fuel consumed while instantiating the Component.
    pub startup_fuel: u64,
    /// Fuel consumed by the call itself.
    pub call_fuel: u64,
    /// Linear memory reserved by the Component, in bytes.
    pub memory_bytes: u64,
}

/// What one worker reports for its single invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerOutcomeV1 {
    /// The export returned a value.
    Completed(WorkerCompletionV1),
    /// The engine stopped the invocation with a closed failure.
    Failed(WorkerFailureV1),
    /// The Component trapped with a canonical trap class.
    Trapped(WorkerTrapClassV1),
}

/// Encode one request envelope.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] when a field exceeds a bound that the
/// decoder enforces: the Component or invocation size, the world or a
/// feature length, or the feature count.
pub fn encode_worker_request_v1(
    request: &WorkerRequestV1,
) -> Result<Vec<u8>, WorkerEnvelopeErrorV1> {
    request_within_bounds(request)
        .then(|| request_bytes(request))
        .ok_or(WorkerEnvelopeErrorV1)
}

fn request_within_bounds(request: &WorkerRequestV1) -> bool {
    let negotiation = &request.negotiation;
    request.component.len() <= MAX_WORKER_COMPONENT_BYTES_V1
        && request.invocation.len() <= MAX_WORKER_INVOCATION_BYTES_V1
        && negotiation.world.len() <= MAX_TEXT_BYTES
        && negotiation.required_features.len() <= MAX_FEATURES
        && negotiation
            .required_features
            .iter()
            .all(|feature| feature.len() <= MAX_TEXT_BYTES)
}

fn request_bytes(request: &WorkerRequestV1) -> Vec<u8> {
    let negotiation = &request.negotiation;
    let limits = &request.limits;
    let mut out = Vec::new();
    array(&mut out, REQUEST_FIELDS);
    text(&mut out, WORKER_REQUEST_MAGIC_V1);
    unsigned(&mut out, VERSION);
    unsigned(&mut out, request.export as u64);
    byte_string(&mut out, &request.component);
    array(&mut out, NEGOTIATION_FIELDS);
    text(&mut out, &negotiation.world);
    unsigned(&mut out, u64::from(negotiation.abi_major));
    unsigned(&mut out, u64::from(negotiation.abi_minor));
    array(&mut out, negotiation.required_features.len() as u64);
    for feature in &negotiation.required_features {
        text(&mut out, feature);
    }
    byte_string(&mut out, &negotiation.pmf1_digest);
    byte_string(&mut out, &negotiation.release_digest);
    array(&mut out, LIMIT_FIELDS);
    for member in [
        limits.memory_bytes,
        limits.fuel,
        limits.host_calls,
        limits.event_count,
        limits.event_bytes,
        limits.state_bytes,
        limits.log_calls,
        limits.log_bytes,
    ] {
        unsigned(&mut out, member);
    }
    unsigned(&mut out, request.simulation_time);
    byte_string(&mut out, &request.invocation);
    out
}

/// Decode one complete request envelope.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] for any malformed, non-canonical,
/// truncated, trailing or out-of-bounds content.
pub fn decode_worker_request_v1(bytes: &[u8]) -> Result<WorkerRequestV1, WorkerEnvelopeErrorV1> {
    let mut reader = EnvelopeReader::new(bytes);
    reader.fixed_array(REQUEST_FIELDS)?;
    header(&mut reader, WORKER_REQUEST_MAGIC_V1)?;
    let export = coded(&mut reader, &WorkerExportV1::ALL)?;
    let component = reader.byte_string(MAX_WORKER_COMPONENT_BYTES_V1)?.to_vec();
    let negotiation = negotiation(&mut reader)?;
    let limits = limits(&mut reader)?;
    let simulation_time = reader.unsigned()?;
    let invocation = reader.byte_string(MAX_WORKER_INVOCATION_BYTES_V1)?.to_vec();
    reader.finish()?;
    Ok(WorkerRequestV1 {
        export,
        component,
        negotiation,
        limits,
        simulation_time,
        invocation,
    })
}

fn negotiation(
    reader: &mut EnvelopeReader<'_>,
) -> Result<WorkerNegotiationV1, WorkerEnvelopeErrorV1> {
    reader.fixed_array(NEGOTIATION_FIELDS)?;
    let world = reader.text(MAX_TEXT_BYTES)?.to_owned();
    let abi_major = small(reader)?;
    let abi_minor = small(reader)?;
    let count = reader.array(MAX_FEATURES)?;
    let required_features = (0..count)
        .map(|_| reader.text(MAX_TEXT_BYTES).map(str::to_owned))
        .collect::<Result<_, _>>()?;
    Ok(WorkerNegotiationV1 {
        world,
        abi_major,
        abi_minor,
        required_features,
        pmf1_digest: reader.bytes()?,
        release_digest: reader.bytes()?,
    })
}

fn limits(reader: &mut EnvelopeReader<'_>) -> Result<DeterministicBudgetV1, WorkerEnvelopeErrorV1> {
    reader.fixed_array(LIMIT_FIELDS)?;
    Ok(DeterministicBudgetV1 {
        memory_bytes: reader.unsigned()?,
        fuel: reader.unsigned()?,
        host_calls: reader.unsigned()?,
        event_count: reader.unsigned()?,
        event_bytes: reader.unsigned()?,
        state_bytes: reader.unsigned()?,
        log_calls: reader.unsigned()?,
        log_bytes: reader.unsigned()?,
    })
}

/// Encode one response envelope.
#[must_use]
pub fn encode_worker_response_v1(outcome: &WorkerOutcomeV1) -> Vec<u8> {
    let mut out = Vec::new();
    array(&mut out, RESPONSE_FIELDS);
    text(&mut out, WORKER_RESPONSE_MAGIC_V1);
    unsigned(&mut out, VERSION);
    match outcome {
        WorkerOutcomeV1::Completed(completion) => {
            array(&mut out, 5);
            unsigned(&mut out, COMPLETED);
            byte_string(&mut out, &completion.payload);
            unsigned(&mut out, completion.startup_fuel);
            unsigned(&mut out, completion.call_fuel);
            unsigned(&mut out, completion.memory_bytes);
        }
        WorkerOutcomeV1::Failed(failure) => {
            array(&mut out, 2);
            unsigned(&mut out, FAILED);
            unsigned(&mut out, *failure as u64);
        }
        WorkerOutcomeV1::Trapped(class) => {
            array(&mut out, 2);
            unsigned(&mut out, TRAPPED);
            unsigned(&mut out, *class as u64);
        }
    }
    out
}

/// Decode one complete response envelope.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] for any malformed, non-canonical,
/// truncated, trailing or unknown content.
pub fn decode_worker_response_v1(bytes: &[u8]) -> Result<WorkerOutcomeV1, WorkerEnvelopeErrorV1> {
    let mut reader = EnvelopeReader::new(bytes);
    reader.fixed_array(RESPONSE_FIELDS)?;
    header(&mut reader, WORKER_RESPONSE_MAGIC_V1)?;
    let members = reader.array(5)?;
    let outcome = match (reader.unsigned()?, members) {
        (COMPLETED, 5) => completion(&mut reader).map(WorkerOutcomeV1::Completed),
        (FAILED, 2) => coded(&mut reader, &WorkerFailureV1::ALL).map(WorkerOutcomeV1::Failed),
        (TRAPPED, 2) => coded(&mut reader, &WorkerTrapClassV1::ALL).map(WorkerOutcomeV1::Trapped),
        _ => Err(WorkerEnvelopeErrorV1),
    }?;
    reader.finish()?;
    Ok(outcome)
}

fn completion(
    reader: &mut EnvelopeReader<'_>,
) -> Result<WorkerCompletionV1, WorkerEnvelopeErrorV1> {
    Ok(WorkerCompletionV1 {
        payload: reader.byte_string(usize::MAX)?.to_vec(),
        startup_fuel: reader.unsigned()?,
        call_fuel: reader.unsigned()?,
        memory_bytes: reader.unsigned()?,
    })
}

/// The magic text and version that open every envelope.
fn header(reader: &mut EnvelopeReader<'_>, magic: &str) -> Result<(), WorkerEnvelopeErrorV1> {
    let valid = reader.exact_text(magic)? && reader.unsigned()? == VERSION;
    valid.then_some(()).ok_or(WorkerEnvelopeErrorV1)
}

/// A wire code that names one entry of `all`.
fn coded<T: Copy>(reader: &mut EnvelopeReader<'_>, all: &[T]) -> Result<T, WorkerEnvelopeErrorV1> {
    let code = reader.unsigned()?;
    usize::try_from(code)
        .ok()
        .and_then(|index| all.get(index).copied())
        .ok_or(WorkerEnvelopeErrorV1)
}

fn small(reader: &mut EnvelopeReader<'_>) -> Result<u16, WorkerEnvelopeErrorV1> {
    u16::try_from(reader.unsigned()?).map_err(|_| WorkerEnvelopeErrorV1)
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    let width = match value {
        0..=23 => {
            out.push(tag | bytes[7]);
            return;
        }
        24..=0xff => (0x18, 1),
        0x100..=0xffff => (0x19, 2),
        0x1_0000..=0xffff_ffff => (0x1a, 4),
        _ => (0x1b, 8),
    };
    out.push(tag | width.0);
    out.extend_from_slice(&bytes[8 - width.1..]);
}

fn unsigned(out: &mut Vec<u8>, value: u64) {
    head(out, 0, value);
}

fn byte_string(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn array(out: &mut Vec<u8>, members: u64) {
    head(out, 4, members);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
