//! Closed load and invocation outcomes.
//!
//! A failed invocation returns only the closed
//! [`CommunityPluginHostErrorV1`]: no guest output, log or runtime message
//! survives it. A completed invocation returns the guest's validated typed
//! return, which may be the guest's own `plugin-error`.

use std::fmt;

use pos_runtime::community_plugin_host::CommunityPluginHostErrorV1;
use wasmtime::Trap;

use crate::host_v1::HostFault;
use crate::runtime::trap_outcome;

/// Why a Component could not be loaded.
///
/// Every refusal is the closed `IncompatibleAbi`, a pre-execution rejection
/// (owner decision of 2026-10-06): see the `From` conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    /// The bytes are not a valid Component for the pinned engine.
    InvalidComponent,
    /// The Component imports a function that is not a `host-v1` function with
    /// its exact type, or anything else the `host-v1` linker does not provide.
    ImportDenied,
    /// `guest-v1` does not export `describe`, `reduce` and `drive` as functions.
    MissingGuestExport,
    /// A `describe`, `reduce` or `drive` export does not have its exact WIT
    /// signature.
    MistypedGuestExport,
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidComponent => "not a valid community Plugin Component",
            Self::ImportDenied => "community Plugin Component import denied",
            Self::MissingGuestExport => "community Plugin Component lacks a guest-v1 export",
            Self::MistypedGuestExport => "community Plugin guest-v1 export has the wrong type",
        })
    }
}

impl std::error::Error for LoadError {}

impl From<LoadError> for CommunityPluginHostErrorV1 {
    /// Every load refusal is `IncompatibleAbi`.
    fn from(_: LoadError) -> Self {
        Self::IncompatibleAbi
    }
}

/// The negotiated record's profile does not pin this engine's runtime.
///
/// Execution requires the profile's pinned runtime to equal
/// [`crate::runtime::pinned_runtime`]: the same version, features, Engine
/// configuration and complete trap table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeNotPinnedV1;

impl fmt::Display for RuntimeNotPinnedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("execution profile does not pin this engine's runtime")
    }
}

impl std::error::Error for RuntimeNotPinnedV1 {}

/// Classify the error that ended an invocation.
///
/// A host refusal maps to its own error, and a trap to its pinned trap-table
/// outcome. Any other error is the host's own Canonical ABI lift or lowering
/// failing on guest-provided values, such as a guest return that does not
/// lift: `InvalidGuestOutput`, never a trap.
///
/// In Wasmtime 49.0.2 the host lifts a guest return in Rust and reports a
/// malformed value with a plain error, never a `Trap` code: for example
/// `bail!("list pointer/length out of bounds of memory")` in
/// `src/runtime/component/func/typed.rs` and the field and case checks in
/// `src/runtime/component/values.rs`. The lift trap codes
/// (`InvalidChar`, `ListOutOfBounds`, ...) are raised only by fused adapters
/// compiled in `wasmtime-environ`'s `src/fact/trampoline.rs`, between
/// Components inside one guest.
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
    fn refusals_have_stable_messages() {
        let messages = [
            (
                LoadError::InvalidComponent,
                "not a valid community Plugin Component",
            ),
            (
                LoadError::ImportDenied,
                "community Plugin Component import denied",
            ),
            (
                LoadError::MissingGuestExport,
                "community Plugin Component lacks a guest-v1 export",
            ),
            (
                LoadError::MistypedGuestExport,
                "community Plugin guest-v1 export has the wrong type",
            ),
        ];
        for (refusal, message) in messages {
            assert_eq!(refusal.to_string(), message);
            let error: &dyn std::error::Error = &refusal;
            assert!(error.source().is_none());
        }
        assert_eq!(
            RuntimeNotPinnedV1.to_string(),
            "execution profile does not pin this engine's runtime"
        );
        let error: &dyn std::error::Error = &RuntimeNotPinnedV1;
        assert!(error.source().is_none());
    }

    #[test]
    fn every_load_refusal_is_incompatible_abi() {
        let refusals = [
            LoadError::InvalidComponent,
            LoadError::ImportDenied,
            LoadError::MissingGuestExport,
            LoadError::MistypedGuestExport,
        ];
        for refusal in refusals {
            assert_eq!(Error::from(refusal), Error::IncompatibleAbi);
        }
    }

    #[test]
    fn host_faults_traps_and_lift_failures_map_to_closed_errors() {
        let cases = [
            (
                wasmtime::Error::new(HostFault::MemoryLimit),
                Error::MemoryLimitExceeded,
            ),
            (
                wasmtime::Error::new(HostFault::HostCallLimit),
                Error::HostCallLimitExceeded,
            ),
            (wasmtime::Error::new(Trap::OutOfFuel), Error::FuelExhausted),
            (
                wasmtime::Error::new(Trap::Interrupt),
                Error::OperationalWatchdogStop,
            ),
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
