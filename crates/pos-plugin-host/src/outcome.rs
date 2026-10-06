//! Closed load and invocation outcomes.
//!
//! A failed invocation returns only the closed
//! [`CommunityPluginHostErrorV1`]: no guest output, log or runtime message
//! survives it. A completed invocation returns the guest's validated typed
//! return, which may be the guest's own `plugin-error`.

use pos_runtime::community_plugin_host::CommunityPluginHostErrorV1;
use wasmtime::Trap;

use crate::contract::GuestPluginErrorV1;
use crate::host_v1::{HostFault, OperationalLogRecord};
use crate::runtime::trap_outcome;

/// Why a Component could not be loaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    /// The bytes are not a valid Component for the pinned engine.
    InvalidComponent,
    /// The Component imports a function that is not a `host-v1` function with
    /// its exact type, or anything else the `host-v1` linker does not provide.
    ImportDenied,
    /// `guest-v1` does not export `describe`, `reduce` and `drive` as functions.
    MissingGuestExport,
}

/// The negotiated record's profile does not pin this engine's runtime.
///
/// Execution requires the profile's pinned runtime to equal
/// [`crate::runtime::pinned_runtime`]: the same version, features, Engine
/// configuration and complete trap table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNotPinnedV1;

/// The guest's validated return: its value, or its own `plugin-error`.
pub type GuestReturnV1<T> = Result<T, GuestPluginErrorV1>;

/// Deterministic resource use of one completed invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeteringV1 {
    /// Fuel consumed while instantiating the Component.
    pub startup_fuel: u64,
    /// Fuel consumed by the call itself.
    pub call_fuel: u64,
    /// Linear memory reserved across all of the Component's memories, in bytes.
    pub memory_bytes: u64,
    /// `host-v1` calls made.
    pub host_calls: u64,
}

/// One completed invocation: the guest's validated return and its metering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationReportV1<T> {
    /// The guest's validated typed return.
    pub result: GuestReturnV1<T>,
    /// Fuel, memory and host calls the invocation used.
    pub metering: MeteringV1,
    /// Accepted `record-operational-log` calls, in call order.
    ///
    /// Operational only: never an authoritative input or output.
    pub operational_log: Vec<OperationalLogRecord>,
}

/// Classify the error that ended an invocation.
///
/// A host refusal maps to its own error, and a trap to its pinned trap-table
/// outcome. Any other error is the host's own Canonical ABI lift or lowering
/// failing on guest-provided values, such as a guest return that does not
/// lift: `InvalidGuestOutput`, never a trap.
pub(crate) fn classify(error: &wasmtime::Error) -> CommunityPluginHostErrorV1 {
    error.downcast_ref::<HostFault>().map_or_else(
        || {
            error
                .downcast_ref::<Trap>()
                .map_or(CommunityPluginHostErrorV1::InvalidGuestOutput, |trap| {
                    trap_outcome(*trap).error()
                })
        },
        |fault| fault.error(),
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_runtime::community_plugin_host::{ComponentTrapClassV1, TrapReproductionV1};

    use super::*;

    type Error = CommunityPluginHostErrorV1;

    #[test]
    fn host_faults_traps_and_lift_failures_map_to_closed_errors() {
        let cases = [
            (wasmtime::Error::new(HostFault::MemoryLimit), Error::MemoryLimitExceeded),
            (wasmtime::Error::new(HostFault::HostCallLimit), Error::HostCallLimitExceeded),
            (wasmtime::Error::new(Trap::OutOfFuel), Error::FuelExhausted),
            (wasmtime::Error::new(Trap::Interrupt), Error::OperationalWatchdogStop),
            (
                wasmtime::Error::new(Trap::StackOverflow),
                Error::ComponentTrap {
                    class: ComponentTrapClassV1::StackExhausted,
                    reproduction: TrapReproductionV1::Unverified,
                },
            ),
            (
                wasmtime::Error::new(Trap::NullReference),
                Error::ComponentTrap {
                    class: ComponentTrapClassV1::Other,
                    reproduction: TrapReproductionV1::Unverified,
                },
            ),
            (
                wasmtime::Error::msg("list pointer/length out of bounds of memory"),
                Error::InvalidGuestOutput,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify(&error), expected);
        }
    }
}
