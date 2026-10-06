//! The pinned runtime identity that an execution profile records.
//!
//! ADR-061 revision 4 decision 2 records the exact Wasmtime version, its
//! resolved feature set, the Engine configuration and the trap table in the
//! execution profile. This module is their single source: the engine builds
//! its configuration from [`PINNED_ENGINE_CONFIG`], and [`pinned_runtime`]
//! derives the trap table from the pinned `wasmtime::Trap` codes themselves.

use pos_runtime::community_plugin_host::{
    CommunityPluginProfileErrorV1, ComponentTrapClassV1, PinnedComponentRuntimeV1,
    PinnedEngineConfigV1, TrapOutcomeV1, TrapTableEntryV1,
};
use wasmtime::Trap;

/// Exact Wasmtime release of the host (ADR-061 revision 4, decision 2).
///
/// A new pin is a new execution-profile version.
pub const WASMTIME_VERSION: &str = "49.0.2";

/// Pinned Wasm stack ceiling, in bytes, for every invocation.
///
/// A deeper guest call stack traps with `StackOverflow`.
pub const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// The resolved Wasmtime feature set, sorted.
///
/// `scripts/check_wasmtime_feature_pin.py` fails CI when Cargo resolves any
/// other set; a test keeps its list equal to this one.
pub const RESOLVED_WASMTIME_FEATURES: [&str; 6] = [
    "component-model",
    "cranelift",
    "once_cell",
    "runtime",
    "std",
    "wasmtime-jit-icache-coherence",
];

/// The pinned Engine configuration that the engine applies and profiles record.
pub const PINNED_ENGINE_CONFIG: PinnedEngineConfigV1 = PinnedEngineConfigV1 {
    max_wasm_stack: MAX_WASM_STACK_BYTES as u64,
    consume_fuel: true,
    epoch_interruption: true,
};

/// The runtime identity of this engine, for the execution profile.
///
/// The trap table has one row for every `wasmtime::Trap` code of the pinned
/// version, in code order, so it names `OutOfFuel`, `Interrupt` and every
/// code the revision 4 table does not list.
///
/// # Errors
///
/// Returns the profile's trap-table rejection; the pinned table satisfies it,
/// and a test proves that.
pub fn pinned_runtime() -> Result<PinnedComponentRuntimeV1, CommunityPluginProfileErrorV1> {
    PinnedComponentRuntimeV1::new(
        WASMTIME_VERSION.to_owned(),
        RESOLVED_WASMTIME_FEATURES.map(str::to_owned).to_vec(),
        PINNED_ENGINE_CONFIG,
        trap_table(),
    )
}

/// Whether `runtime` records exactly this engine's runtime.
///
/// It compares the same values [`pinned_runtime`] records, without building
/// (and so without re-validating) a second runtime.
pub(crate) fn is_pinned_runtime(runtime: &PinnedComponentRuntimeV1) -> bool {
    runtime.wasmtime_version() == WASMTIME_VERSION
        && runtime.resolved_features() == RESOLVED_WASMTIME_FEATURES
        && runtime.engine() == PINNED_ENGINE_CONFIG
        && runtime.trap_table() == trap_table().as_slice()
}

/// One row for every trap code of the pinned version, in code order.
fn trap_table() -> Vec<TrapTableEntryV1> {
    (0..=u8::MAX)
        .filter_map(Trap::from_u8)
        .map(|trap| TrapTableEntryV1 {
            trap_code: format!("{trap:?}"),
            outcome: trap_outcome(trap),
        })
        .collect()
}

/// The ADR-061 revision 4 decision 6 outcome of one pinned trap code.
///
/// Revision 5 decision 3 applies the table to the codes Wasmtime 49.0.2
/// defines, so `AlwaysTrapAdapter` is absent and every unlisted code is
/// `other`. A canonical-ABI lift failure of a guest return is not a trap at
/// all: the host's lift reports it without a trap code, and the engine maps
/// it to `InvalidGuestOutput`.
pub(crate) const fn trap_outcome(trap: Trap) -> TrapOutcomeV1 {
    match trap {
        Trap::OutOfFuel => TrapOutcomeV1::FuelExhausted,
        Trap::Interrupt => TrapOutcomeV1::WatchdogStop,
        Trap::UnreachableCodeReached => TrapOutcomeV1::Trap(ComponentTrapClassV1::Unreachable),
        Trap::MemoryOutOfBounds | Trap::HeapMisaligned | Trap::ArrayOutOfBounds => {
            TrapOutcomeV1::Trap(ComponentTrapClassV1::MemoryOutOfBounds)
        }
        Trap::TableOutOfBounds => TrapOutcomeV1::Trap(ComponentTrapClassV1::TableOutOfBounds),
        Trap::IndirectCallToNull | Trap::BadSignature => {
            TrapOutcomeV1::Trap(ComponentTrapClassV1::IndirectCall)
        }
        Trap::IntegerOverflow | Trap::IntegerDivisionByZero | Trap::BadConversionToInteger => {
            TrapOutcomeV1::Trap(ComponentTrapClassV1::IntegerArithmetic)
        }
        Trap::StackOverflow => TrapOutcomeV1::Trap(ComponentTrapClassV1::StackExhausted),
        _ => TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    use ComponentTrapClassV1 as Class;

    /// Every Wasmtime 49.0.2 trap code, in code order.
    const PINNED_TRAP_CODES: [&str; 50] = [
        "StackOverflow",
        "MemoryOutOfBounds",
        "HeapMisaligned",
        "TableOutOfBounds",
        "IndirectCallToNull",
        "BadSignature",
        "IntegerOverflow",
        "IntegerDivisionByZero",
        "BadConversionToInteger",
        "UnreachableCodeReached",
        "Interrupt",
        "OutOfFuel",
        "AtomicWaitNonSharedMemory",
        "NullReference",
        "ArrayOutOfBounds",
        "AllocationTooLarge",
        "CastFailure",
        "CannotEnterComponent",
        "NoAsyncResult",
        "UnhandledTag",
        "ContinuationAlreadyConsumed",
        "DisabledOpcode",
        "AsyncDeadlock",
        "CannotLeaveComponent",
        "CannotBlockSyncTask",
        "InvalidChar",
        "DebugAssertStringEncodingFinished",
        "DebugAssertEqualCodeUnits",
        "DebugAssertPointerAligned",
        "DebugAssertUpperBitsUnset",
        "StringOutOfBounds",
        "ListOutOfBounds",
        "InvalidDiscriminant",
        "UnalignedPointer",
        "TaskCancelNotCancelled",
        "TaskCancelOrReturnTwice",
        "SubtaskCancelAfterTerminal",
        "TaskReturnInvalid",
        "WaitableSetDropHasWaiters",
        "SubtaskDropNotResolved",
        "ThreadNewIndirectInvalidType",
        "ThreadNewIndirectUninitialized",
        "BackpressureOverflow",
        "UnsupportedCallbackCode",
        "CannotResumeThread",
        "ConcurrentFutureStreamOp",
        "ReferenceCountOverflow",
        "StreamOpTooBig",
        "WaitableSyncAndAsync",
        "UncaughtException",
    ];

    /// Every row whose outcome is not the `other` class.
    const CLASSIFIED: [(&str, TrapOutcomeV1); 15] = [
        ("StackOverflow", TrapOutcomeV1::Trap(Class::StackExhausted)),
        (
            "MemoryOutOfBounds",
            TrapOutcomeV1::Trap(Class::MemoryOutOfBounds),
        ),
        (
            "HeapMisaligned",
            TrapOutcomeV1::Trap(Class::MemoryOutOfBounds),
        ),
        (
            "TableOutOfBounds",
            TrapOutcomeV1::Trap(Class::TableOutOfBounds),
        ),
        (
            "IndirectCallToNull",
            TrapOutcomeV1::Trap(Class::IndirectCall),
        ),
        ("BadSignature", TrapOutcomeV1::Trap(Class::IndirectCall)),
        (
            "IntegerOverflow",
            TrapOutcomeV1::Trap(Class::IntegerArithmetic),
        ),
        (
            "IntegerDivisionByZero",
            TrapOutcomeV1::Trap(Class::IntegerArithmetic),
        ),
        (
            "BadConversionToInteger",
            TrapOutcomeV1::Trap(Class::IntegerArithmetic),
        ),
        (
            "UnreachableCodeReached",
            TrapOutcomeV1::Trap(Class::Unreachable),
        ),
        ("Interrupt", TrapOutcomeV1::WatchdogStop),
        ("OutOfFuel", TrapOutcomeV1::FuelExhausted),
        (
            "ArrayOutOfBounds",
            TrapOutcomeV1::Trap(Class::MemoryOutOfBounds),
        ),
        // Canonical-ABI lift codes come only from fused adapters inside a
        // Component; the host's own lift of a guest return never traps.
        ("InvalidChar", TrapOutcomeV1::Trap(Class::Other)),
        ("ListOutOfBounds", TrapOutcomeV1::Trap(Class::Other)),
    ];

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
    }

    #[test]
    fn the_trap_table_has_one_row_per_pinned_code_in_code_order() {
        let runtime = ok(pinned_runtime());
        let codes: Vec<&str> = runtime
            .trap_table()
            .iter()
            .map(|entry| entry.trap_code.as_str())
            .collect();
        assert_eq!(codes, PINNED_TRAP_CODES);
        assert!(!codes.contains(&"AlwaysTrapAdapter"));
        for entry in runtime.trap_table() {
            let expected = CLASSIFIED
                .iter()
                .find(|(code, _)| *code == entry.trap_code)
                .map_or(TrapOutcomeV1::Trap(Class::Other), |(_, outcome)| *outcome);
            assert_eq!(entry.outcome, expected, "{}", entry.trap_code);
        }
    }

    #[test]
    fn the_runtime_records_the_pin_features_and_engine_config() {
        let runtime = ok(pinned_runtime());
        assert_eq!(runtime.wasmtime_version(), "49.0.2");
        assert_eq!(runtime.resolved_features(), RESOLVED_WASMTIME_FEATURES);
        assert_eq!(
            runtime.engine(),
            PinnedEngineConfigV1 {
                max_wasm_stack: 524_288,
                consume_fuel: true,
                epoch_interruption: true,
            }
        );
    }

    #[test]
    fn the_pin_checker_and_the_workspace_pin_record_the_same_runtime() {
        let checker = include_str!("../../../scripts/check_wasmtime_feature_pin.py");
        let listed = checker
            .split_once("RESOLVED_FEATURES = [")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(list, _)| list)
            .unwrap_or_default();
        let features: Vec<&str> = listed
            .split(',')
            .map(|item| item.trim().trim_matches('"'))
            .filter(|item| !item.is_empty())
            .collect();
        assert_eq!(features, RESOLVED_WASMTIME_FEATURES);
        assert!(checker.contains(&format!("VERSION = \"{WASMTIME_VERSION}\"")));
        let workspace = include_str!("../../../Cargo.toml");
        assert!(workspace.contains(&format!("wasmtime = {{ version = \"={WASMTIME_VERSION}\"")));
    }
}
