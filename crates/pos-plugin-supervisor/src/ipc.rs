//! Worker IPC envelopes (ADR-061 revision 4 decision 4, revision 6).
//!
//! The supervisor sends one request envelope to a fresh worker and reads back
//! one response envelope, each in one frame ([`crate::frame`]). Both are
//! canonical CBOR arrays read with `pos-crypto`'s strict reader. Any fault in
//! an envelope is the single closed [`WorkerEnvelopeErrorV1`], which the
//! supervisor reports as the operational `WorkerCrashed`.
//!
//! The request is `["PWQ1", 1, component, negotiation, watchdog_millis,
//! simulation_time, call]`:
//! - `negotiation` is the supervisor's negotiated record, `[world, plugin_id,
//!   pmf1_digest, release_digest, abi_major, abi_minor, [declared_min,
//!   declared_max], [feature...], [capability...], mode, [limit x 8],
//!   [profile_digest?]]`. A capability is its nine PMF1 fields in order;
//!   `mode` is 0 for Local and 1 for Air-Gapped; the limits are the
//!   `DeterministicBudgetV1` members in PMF1 order; the execution profile
//!   digest is an array of zero items (the record has no digest) or one
//!   32-byte string;
//! - `call` is `[0]` for `describe`, or `[1, invocation]` for `reduce` and
//!   `[2, invocation]` for `drive`.
//!
//! The response is `["PWR1", 1, outcome]`, where `outcome` is one of:
//! - `[0, return, metering, log]`: `describe` completed, and `return` is
//!   `[0, descriptor]` or `[1, plugin_error]`;
//! - `[1, return, metering, log]`: `reduce` or `drive` completed, and
//!   `return` is `[0, output]` or `[1, plugin_error]`;
//! - `[2, failure]`: a closed engine failure, by its position in
//!   [`WORKER_FAILURES_V1`];
//! - `[3, trap_class]`: `ComponentTrap`, by the class's position in
//!   [`WORKER_TRAP_CLASSES_V1`], always unverified.
//!
//! The contract records are encoded as in `contract` (WIT field order).

mod contract;
mod wire;

use pos_crypto::plugin_execution::{DeterministicBudgetV1, PluginCapabilityDescriptorV1};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, CommunityPluginModeV1, ComponentTrapClassV1, GuestReturnV1,
    HostInputs, InvocationReportV1, NegotiatedTransportV1, PluginDescriptorV1, PluginInvocationV1,
    PluginOutputV1, TrapReproductionV1,
};

use self::contract::{
    read_descriptor, read_guest_error, read_invocation, read_log, read_metering, read_output,
    write_descriptor, write_guest_error, write_invocation, write_log, write_metering, write_output,
};
use crate::launch::MODES;

use self::wire::{
    read_bytes, read_code, read_digests, read_list, read_text, read_u16, require, Decoded,
    EnvelopeReader, Writer,
};

/// Magic text of a worker request envelope.
pub const WORKER_REQUEST_MAGIC_V1: &str = "PWQ1";
/// Magic text of a worker response envelope.
pub const WORKER_RESPONSE_MAGIC_V1: &str = "PWR1";
/// Largest Component a request carries: the 32 MiB PMF1 V1 field 9 bound.
pub const MAX_WORKER_COMPONENT_BYTES_V1: usize = 33_554_432;
/// The closed engine failures a response carries, in wire-code order.
pub const WORKER_FAILURES_V1: [CommunityPluginHostErrorV1; 8] = [
    CommunityPluginHostErrorV1::InvalidInvocation,
    CommunityPluginHostErrorV1::IncompatibleAbi,
    CommunityPluginHostErrorV1::InvalidGuestOutput,
    CommunityPluginHostErrorV1::FuelExhausted,
    CommunityPluginHostErrorV1::MemoryLimitExceeded,
    CommunityPluginHostErrorV1::HostCallLimitExceeded,
    CommunityPluginHostErrorV1::OutputLimitExceeded,
    CommunityPluginHostErrorV1::OperationalWatchdogStop,
];
/// The canonical trap classes a response carries, in wire-code order.
pub const WORKER_TRAP_CLASSES_V1: [ComponentTrapClassV1; 7] = [
    ComponentTrapClassV1::Unreachable,
    ComponentTrapClassV1::MemoryOutOfBounds,
    ComponentTrapClassV1::TableOutOfBounds,
    ComponentTrapClassV1::IndirectCall,
    ComponentTrapClassV1::IntegerArithmetic,
    ComponentTrapClassV1::StackExhausted,
    ComponentTrapClassV1::Other,
];

const VERSION: u64 = 1;
/// WIT bound on IDs and other bounded text, in bytes.
const MAX_TEXT_BYTES: usize = 128;
const MAX_PATTERN_BYTES: usize = 512;
const MAX_LIST: usize = 256;

/// A malformed, non-canonical, truncated, out-of-bounds or unencodable
/// worker envelope.
///
/// Public so the worker-side helpers can return it; every caller maps it to a
/// crash, so nothing inspects it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("malformed community Plugin worker envelope")]
pub struct WorkerEnvelopeErrorV1;

/// The export one worker invokes, with its input.
///
/// `migrate-state` has no call: a V1 host never invokes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerCallV1 {
    /// `describe`.
    Describe,
    /// `reduce` with its invocation.
    Reduce(PluginInvocationV1),
    /// `drive` with its invocation.
    Drive(PluginInvocationV1),
}

/// One invocation request from the supervisor to a fresh worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRequestV1 {
    /// The verified Component bytes.
    pub component: Vec<u8>,
    /// The supervisor's negotiated record.
    pub negotiation: NegotiatedTransportV1,
    /// The supervisor's wall-time watchdog, in milliseconds.
    pub watchdog_millis: u64,
    /// Deterministic `host-v1` values.
    pub host_inputs: HostInputs,
    /// The export and its input.
    pub call: WorkerCallV1,
}

/// What a completed call returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerReturnV1 {
    /// `describe` returned.
    Described(InvocationReportV1<PluginDescriptorV1>),
    /// `reduce` or `drive` returned.
    Produced(InvocationReportV1<PluginOutputV1>),
}

/// What one worker reports for its single invocation.
pub type WorkerOutcomeV1 = Result<WorkerReturnV1, CommunityPluginHostErrorV1>;

/// Encode one request envelope.
///
/// The encoder checks only the Component size, the one large field, before it
/// writes. Every other bound holds by construction: the negotiated record
/// comes from negotiation, the invocation from `PluginInvocationV1::validate`,
/// and the fixed-size fields from their types. The worker's decoder enforces
/// all of them again, so a value that broke one would be a protocol fault at
/// the worker (`WorkerCrashed`), never a committed result. Encoding does not
/// decode the output back; the tests round-trip values at each bound.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] when the Component exceeds
/// [`MAX_WORKER_COMPONENT_BYTES_V1`].
pub fn encode_worker_request_v1(
    request: &WorkerRequestV1,
) -> Result<Vec<u8>, WorkerEnvelopeErrorV1> {
    require(request.component.len() <= MAX_WORKER_COMPONENT_BYTES_V1)?;
    let mut writer = Writer::default();
    writer
        .array(7)
        .text(WORKER_REQUEST_MAGIC_V1)
        .unsigned(VERSION)
        .bytes(&request.component);
    write_negotiation(&mut writer, &request.negotiation);
    writer
        .unsigned(request.watchdog_millis)
        .unsigned(request.host_inputs.simulation_time);
    match &request.call {
        WorkerCallV1::Describe => {
            writer.array(1).unsigned(0);
        }
        WorkerCallV1::Reduce(invocation) => {
            writer.array(2).unsigned(1);
            write_invocation(&mut writer, invocation);
        }
        WorkerCallV1::Drive(invocation) => {
            writer.array(2).unsigned(2);
            write_invocation(&mut writer, invocation);
        }
    }
    Ok(writer.bytes)
}

/// Decode one complete request envelope.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] for any malformed, non-canonical,
/// truncated, trailing or out-of-bounds content.
pub fn decode_worker_request_v1(bytes: &[u8]) -> Result<WorkerRequestV1, WorkerEnvelopeErrorV1> {
    let mut reader = EnvelopeReader::new(bytes);
    reader.fixed_array(7)?;
    header(&mut reader, WORKER_REQUEST_MAGIC_V1)?;
    let request = WorkerRequestV1 {
        component: read_bytes(&mut reader, MAX_WORKER_COMPONENT_BYTES_V1)?,
        negotiation: read_negotiation(&mut reader)?,
        watchdog_millis: reader.unsigned()?,
        host_inputs: HostInputs {
            simulation_time: reader.unsigned()?,
        },
        call: read_call(&mut reader)?,
    };
    reader.finish()?;
    Ok(request)
}

fn read_call(reader: &mut EnvelopeReader<'_>) -> Decoded<WorkerCallV1> {
    let members = reader.array(2)?;
    let call = read_code(reader, 3)?;
    require(members == if call == 0 { 1 } else { 2 })?;
    Ok(match call {
        0 => WorkerCallV1::Describe,
        1 => WorkerCallV1::Reduce(read_invocation(reader)?),
        _ => WorkerCallV1::Drive(read_invocation(reader)?),
    })
}

fn write_negotiation(writer: &mut Writer, negotiation: &NegotiatedTransportV1) {
    let (declared_min, declared_max) = negotiation.declared_minors;
    let limits = &negotiation.limits;
    writer
        .array(12)
        .text(&negotiation.world)
        .text(&negotiation.plugin_id)
        .bytes(&negotiation.pmf1_digest)
        .bytes(&negotiation.release_digest)
        .unsigned(u64::from(negotiation.abi_major))
        .unsigned(u64::from(negotiation.abi_minor))
        .array(2)
        .unsigned(u64::from(declared_min))
        .unsigned(u64::from(declared_max))
        .list(&negotiation.required_features, |writer, feature| {
            writer.text(feature);
        })
        .list(&negotiation.not_granted_capabilities, write_capability)
        .unsigned(u64::from(
            negotiation.mode == CommunityPluginModeV1::AirGapped,
        ))
        .array(8);
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
        writer.unsigned(member);
    }
    writer.digests(negotiation.execution_profile_digest.as_slice());
}

fn write_capability(writer: &mut Writer, capability: &PluginCapabilityDescriptorV1) {
    writer
        .array(9)
        .text(&capability.capability_id)
        .text(&capability.operation)
        .text(&capability.resource_pattern)
        .text(&capability.purpose)
        .text(&capability.audience)
        .boolean(capability.required)
        .unsigned(capability.max_calls)
        .unsigned(capability.max_request_bytes)
        .unsigned(capability.max_response_bytes);
}

fn read_negotiation(reader: &mut EnvelopeReader<'_>) -> Decoded<NegotiatedTransportV1> {
    reader.fixed_array(12)?;
    let world = read_text(reader, MAX_TEXT_BYTES)?;
    let plugin_id = read_text(reader, MAX_TEXT_BYTES)?;
    let pmf1_digest = reader.bytes()?;
    let release_digest = reader.bytes()?;
    let abi_major = read_u16(reader)?;
    let abi_minor = read_u16(reader)?;
    reader.fixed_array(2)?;
    let declared_minors = (read_u16(reader)?, read_u16(reader)?);
    let required_features =
        read_list(reader, MAX_LIST, |reader| read_text(reader, MAX_TEXT_BYTES))?;
    let not_granted_capabilities = read_list(reader, MAX_LIST, read_capability)?;
    let mode = read_mode(reader)?;
    let (limits, execution_profile_digest) = read_limits_and_digest(reader)?;
    Ok(NegotiatedTransportV1 {
        world,
        plugin_id,
        pmf1_digest,
        release_digest,
        abi_major,
        abi_minor,
        declared_minors,
        required_features,
        not_granted_capabilities,
        mode,
        limits,
        execution_profile_digest,
    })
}

/// The mode, by its wire code.
fn read_mode(reader: &mut EnvelopeReader<'_>) -> Decoded<CommunityPluginModeV1> {
    Ok(MODES[read_code(reader, MODES.len())?])
}

/// The optional profile digest: an array of zero items or one digest.
fn read_profile_digest(reader: &mut EnvelopeReader<'_>) -> Decoded<Option<[u8; 32]>> {
    Ok(read_digests(reader, 1)?.into_iter().next())
}

/// The limits and the profile digest that follow them.
fn read_limits_and_digest(
    reader: &mut EnvelopeReader<'_>,
) -> Decoded<(DeterministicBudgetV1, Option<[u8; 32]>)> {
    Ok((read_limits(reader)?, read_profile_digest(reader)?))
}

fn read_capability(reader: &mut EnvelopeReader<'_>) -> Decoded<PluginCapabilityDescriptorV1> {
    reader.fixed_array(9)?;
    Ok(PluginCapabilityDescriptorV1 {
        capability_id: read_text(reader, MAX_TEXT_BYTES)?,
        operation: read_text(reader, MAX_TEXT_BYTES)?,
        resource_pattern: read_text(reader, MAX_PATTERN_BYTES)?,
        purpose: read_text(reader, MAX_TEXT_BYTES)?,
        audience: read_text(reader, MAX_TEXT_BYTES)?,
        required: reader.boolean()?,
        max_calls: reader.unsigned()?,
        max_request_bytes: reader.unsigned()?,
        max_response_bytes: reader.unsigned()?,
    })
}

fn read_limits(reader: &mut EnvelopeReader<'_>) -> Decoded<DeterministicBudgetV1> {
    reader.fixed_array(8)?;
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
///
/// As for the request, the encoder does not re-decode its output: the engine
/// has validated the value, and the supervisor's decoder enforces every bound.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] for an error the wire cannot carry (one
/// outside [`WORKER_FAILURES_V1`], or a reproduced trap).
pub fn encode_worker_response_v1(
    outcome: &WorkerOutcomeV1,
) -> Result<Vec<u8>, WorkerEnvelopeErrorV1> {
    let mut writer = Writer::default();
    writer
        .array(3)
        .text(WORKER_RESPONSE_MAGIC_V1)
        .unsigned(VERSION);
    match outcome {
        Ok(WorkerReturnV1::Described(report)) => {
            write_report(&mut writer, 0, report, write_descriptor);
        }
        Ok(WorkerReturnV1::Produced(report)) => write_report(&mut writer, 1, report, write_output),
        Err(error) => write_error(&mut writer, *error)?,
    }
    Ok(writer.bytes)
}

fn write_report<T>(
    writer: &mut Writer,
    tag: u64,
    report: &InvocationReportV1<T>,
    value: impl FnOnce(&mut Writer, &T),
) {
    writer.array(4).unsigned(tag).array(2);
    match &report.result {
        Ok(result) => {
            writer.unsigned(0);
            value(writer, result);
        }
        Err(error) => {
            writer.unsigned(1);
            write_guest_error(writer, error);
        }
    }
    write_metering(writer, &report.metering);
    write_log(writer, &report.operational_log);
}

fn write_error(
    writer: &mut Writer,
    error: CommunityPluginHostErrorV1,
) -> Result<(), WorkerEnvelopeErrorV1> {
    let code = match error {
        CommunityPluginHostErrorV1::ComponentTrap {
            class,
            reproduction: TrapReproductionV1::Unverified,
        } => WORKER_TRAP_CLASSES_V1
            .iter()
            .position(|candidate| *candidate == class)
            .map(|code| (3, code)),
        other => WORKER_FAILURES_V1
            .iter()
            .position(|candidate| *candidate == other)
            .map(|code| (2, code)),
    };
    let (tag, code) = code.ok_or(WorkerEnvelopeErrorV1)?;
    writer.array(2).unsigned(tag).unsigned(code as u64);
    Ok(())
}

/// Decode one complete response envelope.
///
/// # Errors
/// Returns [`WorkerEnvelopeErrorV1`] for any malformed, non-canonical,
/// truncated, trailing, out-of-bounds or unknown content.
pub fn decode_worker_response_v1(bytes: &[u8]) -> Result<WorkerOutcomeV1, WorkerEnvelopeErrorV1> {
    let mut reader = EnvelopeReader::new(bytes);
    reader.fixed_array(3)?;
    header(&mut reader, WORKER_RESPONSE_MAGIC_V1)?;
    let members = reader.array(4)?;
    let tag = read_code(&mut reader, 4)?;
    require(members == if tag < 2 { 4 } else { 2 })?;
    let outcome = match tag {
        0 => read_report(&mut reader, read_descriptor)
            .map(|report| Ok(WorkerReturnV1::Described(report))),
        1 => {
            read_report(&mut reader, read_output).map(|report| Ok(WorkerReturnV1::Produced(report)))
        }
        2 => read_code(&mut reader, WORKER_FAILURES_V1.len())
            .map(|code| Err(WORKER_FAILURES_V1[code])),
        _ => read_code(&mut reader, WORKER_TRAP_CLASSES_V1.len()).map(|code| {
            Err(CommunityPluginHostErrorV1::ComponentTrap {
                class: WORKER_TRAP_CLASSES_V1[code],
                reproduction: TrapReproductionV1::Unverified,
            })
        }),
    }?;
    reader.finish()?;
    Ok(outcome)
}

fn read_report<T>(
    reader: &mut EnvelopeReader<'_>,
    value: impl FnOnce(&mut EnvelopeReader<'_>) -> Decoded<T>,
) -> Decoded<InvocationReportV1<T>> {
    reader.fixed_array(2)?;
    let result: GuestReturnV1<T> = match read_code(reader, 2)? {
        0 => Ok(value(reader)?),
        _ => Err(read_guest_error(reader)?),
    };
    Ok(InvocationReportV1 {
        result,
        metering: read_metering(reader)?,
        operational_log: read_log(reader)?,
    })
}

/// The magic text and version that open every envelope.
fn header(reader: &mut EnvelopeReader<'_>, magic: &str) -> Decoded<()> {
    let valid = reader.exact_text(magic)? && reader.unsigned()? == VERSION;
    require(valid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
