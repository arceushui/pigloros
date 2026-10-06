//! The in-worker engine seam: the only worker code that runs a Component.
//!
//! [`invoke`] takes one decoded request and returns the outcome the worker
//! reports. Everything else in the worker is engine-agnostic.
//!
//! This adapter drives the #539 prototype engine of `pos-plugin-host`. When the
//! #541 engine lands, this module is rewired to it:
//! - #541 lowers the canonical `plugin-invocation` record for `reduce` and
//!   `drive`; until then only `describe`, which takes no input, runs, and any
//!   other request is `InvalidInvocation`;
//! - #541 validates the guest output, including the `describe` ABI check
//!   against the negotiated tuple the request carries; until then the
//!   payload is the lifted value encoded structurally (see [`encode_value`]);
//! - #541 supplies the closed failure classification and the pinned trap
//!   table; the provisional mapping is in `failure_outcome` and
//!   `trap_class`.
//!
//! The wall-time watchdog is the supervisor's deadline, which kills the worker.
//! The engine's epoch deadline is therefore never reached here; an epoch
//! interrupt would still report `OperationalWatchdogStop`.

use ciborium::value::Value;
use pos_crypto::plugin_worker_ipc::{
    WorkerCompletionV1, WorkerExportV1, WorkerFailureV1, WorkerOutcomeV1, WorkerRequestV1,
    WorkerTrapClassV1,
};
use pos_plugin_host::{
    ComponentHost, GuestExport, HostInputs, InvocationFailure, InvocationLimits, InvocationReport,
    Trap, Val,
};

/// Run one request, or `None` when this platform cannot build the engine.
#[must_use]
pub fn invoke(request: &WorkerRequestV1) -> Option<WorkerOutcomeV1> {
    ComponentHost::new().ok().map(|host| run(&host, request))
}

fn run(host: &ComponentHost, request: &WorkerRequestV1) -> WorkerOutcomeV1 {
    if request.export != WorkerExportV1::Describe || !request.invocation.is_empty() {
        return WorkerOutcomeV1::Failed(WorkerFailureV1::InvalidInvocation);
    }
    let Ok(component) = host.load(&request.component) else {
        return WorkerOutcomeV1::Failed(WorkerFailureV1::IncompatibleAbi);
    };
    let limits = InvocationLimits {
        fuel: request.limits.fuel,
        memory_bytes: request.limits.memory_bytes,
        watchdog_epochs: u32::MAX,
    };
    let inputs = HostInputs {
        simulation_time: request.simulation_time,
    };
    host.invoke(&component, GuestExport::Describe, &[], limits, inputs)
        .map_or_else(failure_outcome, |report| completion(&report))
}

fn completion(report: &InvocationReport) -> WorkerOutcomeV1 {
    encode_value(&report.value).map_or(
        WorkerOutcomeV1::Failed(WorkerFailureV1::InvalidGuestOutput),
        |payload| {
            WorkerOutcomeV1::Completed(WorkerCompletionV1 {
                payload,
                startup_fuel: report.startup_fuel,
                call_fuel: report.call_fuel,
                memory_bytes: report.memory_bytes,
            })
        },
    )
}

/// The provisional closed outcome of one prototype-engine failure.
const fn failure_outcome(failure: InvocationFailure) -> WorkerOutcomeV1 {
    let failure = match failure {
        InvocationFailure::FuelExhausted => WorkerFailureV1::FuelExhausted,
        InvocationFailure::MemoryLimitExceeded => WorkerFailureV1::MemoryLimitExceeded,
        InvocationFailure::OperationalWatchdogStop => WorkerFailureV1::OperationalWatchdogStop,
        InvocationFailure::HostCallRejected => WorkerFailureV1::HostCallLimitExceeded,
        InvocationFailure::Rejected => WorkerFailureV1::InvalidInvocation,
        InvocationFailure::ComponentTrap(trap) => {
            return WorkerOutcomeV1::Trapped(trap_class(trap))
        }
    };
    WorkerOutcomeV1::Failed(failure)
}

/// The ADR-061 revision 4 decision 6 class of one trap code.
const fn trap_class(trap: Trap) -> WorkerTrapClassV1 {
    match trap {
        Trap::UnreachableCodeReached => WorkerTrapClassV1::Unreachable,
        Trap::MemoryOutOfBounds | Trap::HeapMisaligned | Trap::ArrayOutOfBounds => {
            WorkerTrapClassV1::MemoryOutOfBounds
        }
        Trap::TableOutOfBounds => WorkerTrapClassV1::TableOutOfBounds,
        Trap::IndirectCallToNull | Trap::BadSignature => WorkerTrapClassV1::IndirectCall,
        Trap::IntegerOverflow | Trap::IntegerDivisionByZero | Trap::BadConversionToInteger => {
            WorkerTrapClassV1::IntegerArithmetic
        }
        Trap::StackOverflow => WorkerTrapClassV1::StackExhausted,
        _ => WorkerTrapClassV1::Other,
    }
}

/// Canonical CBOR of a lifted value, or `None` for a kind outside the world.
///
/// Records and lists are arrays in field and element order, enum and variant
/// cases are their names, `option` is `null` or a one-element array, and
/// `result` is `[0 or 1, payload?]`.
#[must_use]
pub fn encode_value(value: &Val) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    cbor(value)
        .and_then(|value| ciborium::into_writer(&value, &mut out).ok())
        .map(|()| out)
}

fn cbor(value: &Val) -> Option<Value> {
    Some(match value {
        Val::Bool(value) => Value::Bool(*value),
        Val::U8(value) => Value::Integer((*value).into()),
        Val::U16(value) => Value::Integer((*value).into()),
        Val::U32(value) => Value::Integer((*value).into()),
        Val::U64(value) => Value::Integer((*value).into()),
        Val::List(items) => Value::Array(items.iter().map(cbor).collect::<Option<_>>()?),
        Val::Record(fields) => Value::Array(
            fields
                .iter()
                .map(|(_, field)| cbor(field))
                .collect::<Option<_>>()?,
        ),
        Val::Enum(case) => Value::Text(case.clone()),
        Val::Variant(case, payload) => tagged(Value::Text(case.clone()), payload.as_deref())?,
        Val::Option(None) => Value::Null,
        Val::Option(Some(payload)) => Value::Array(vec![cbor(payload)?]),
        Val::Result(Ok(payload)) => tagged(Value::Integer(0.into()), payload.as_deref())?,
        Val::Result(Err(payload)) => tagged(Value::Integer(1.into()), payload.as_deref())?,
        _ => return None,
    })
}

fn tagged(tag: Value, payload: Option<&Val>) -> Option<Value> {
    let payload = payload
        .map(cbor)
        .map_or(Some(None), |payload| payload.map(Some))?;
    Some(Value::Array(std::iter::once(tag).chain(payload).collect()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
