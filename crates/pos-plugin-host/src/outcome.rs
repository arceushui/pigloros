//! Closed load and invocation outcomes.

use wasmtime::component::Val;
use wasmtime::Trap;

use crate::host_v1::{HostFault, OperationalLogRecord};

/// Why a Component could not be loaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    /// The bytes are not a valid Component for the pinned engine.
    InvalidComponent,
    /// The Component needs an import that the `host-v1` linker does not provide.
    ImportDenied,
    /// `guest-v1` does not export `describe`, `reduce` and `drive` as functions.
    MissingGuestExport,
}

/// The lifted result and the measured budget of one successful invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationReport {
    /// The export's lifted return value, not yet validated as guest output.
    pub value: Val,
    /// Fuel consumed while instantiating the Component.
    pub startup_fuel: u64,
    /// Fuel consumed by the call itself.
    pub call_fuel: u64,
    /// Linear memory reserved across all of the Component's memories, in bytes.
    pub memory_bytes: u64,
    /// Accepted `record-operational-log` calls, in call order.
    pub operational_log: Vec<OperationalLogRecord>,
}

/// Why an invocation ended without a result.
///
/// No variant carries guest output, so nothing from a failed invocation can be
/// committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationFailure {
    /// Wasmtime fuel ran out (`Trap::OutOfFuel`): the authoritative `FuelExhausted`.
    FuelExhausted,
    /// The limiter denied linear-memory growth: `MemoryLimitExceeded`.
    MemoryLimitExceeded,
    /// The epoch deadline elapsed (`Trap::Interrupt`): the operational
    /// `OperationalWatchdogStop`, never an authoritative result.
    OperationalWatchdogStop,
    /// A `host-v1` call carried arguments, or exceeded a count, that the host
    /// refuses.
    HostCallRejected,
    /// Any other Wasmtime trap, before #541 maps it to a canonical trap class.
    ComponentTrap(Trap),
    /// Wasmtime refused the invocation without a trap, for example because the
    /// arguments do not match the export's type.
    Rejected,
}

/// Classify the error that ended an invocation.
pub(crate) fn classify(error: &wasmtime::Error) -> InvocationFailure {
    error.downcast_ref::<HostFault>().map_or_else(
        || {
            error
                .downcast_ref::<Trap>()
                .map_or(InvocationFailure::Rejected, |trap| trap_failure(*trap))
        },
        |fault| fault_failure(*fault),
    )
}

const fn trap_failure(trap: Trap) -> InvocationFailure {
    match trap {
        Trap::OutOfFuel => InvocationFailure::FuelExhausted,
        Trap::Interrupt => InvocationFailure::OperationalWatchdogStop,
        other => InvocationFailure::ComponentTrap(other),
    }
}

const fn fault_failure(fault: HostFault) -> InvocationFailure {
    match fault {
        HostFault::CallRejected => InvocationFailure::HostCallRejected,
        HostFault::MemoryLimit => InvocationFailure::MemoryLimitExceeded,
        HostFault::MissingExport => InvocationFailure::Rejected,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn host_faults_and_traps_map_to_closed_failures() {
        let missing = wasmtime::Error::new(HostFault::MissingExport);
        assert_eq!(classify(&missing), InvocationFailure::Rejected);
        let memory = wasmtime::Error::new(HostFault::MemoryLimit);
        assert_eq!(classify(&memory), InvocationFailure::MemoryLimitExceeded);
        let rejected = wasmtime::Error::new(HostFault::CallRejected);
        assert_eq!(classify(&rejected), InvocationFailure::HostCallRejected);
        let fuel = wasmtime::Error::new(Trap::OutOfFuel);
        assert_eq!(classify(&fuel), InvocationFailure::FuelExhausted);
        let interrupt = wasmtime::Error::new(Trap::Interrupt);
        assert_eq!(
            classify(&interrupt),
            InvocationFailure::OperationalWatchdogStop
        );
        let stack = wasmtime::Error::new(Trap::StackOverflow);
        assert_eq!(
            classify(&stack),
            InvocationFailure::ComponentTrap(Trap::StackOverflow)
        );
        let other = wasmtime::Error::msg("not a trap");
        assert_eq!(classify(&other), InvocationFailure::Rejected);
    }
}
