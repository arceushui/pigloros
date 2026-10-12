//! The constant pinned Component runtime of the worker (ADR-061 revision 8).
//!
//! The execution profile of a host records the pinned runtime of the worker,
//! whose digest the worker checks. `pos-plugin-host` derives that runtime
//! from Wasmtime itself; this module states the same data as constants so that
//! a graph without Wasmtime (the conformance adapter) builds the same profile.
//! A test in `pos-plugin-host` proves the two equal, so a Wasmtime change that
//! alters either fails there.

use super::{
    CeilingValuesV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginModeV1, ComponentTrapClassV1, PinnedComponentRuntimeV1, PinnedEngineConfigV1,
    TrapOutcomeV1, TrapTableEntryV1,
};

/// Exact Wasmtime release of the worker.
const PINNED_WASMTIME_VERSION: &str = "49.0.2";

/// The resolved Wasmtime feature set, sorted.
const PINNED_RESOLVED_FEATURES: [&str; 6] = [
    "component-model",
    "cranelift",
    "once_cell",
    "runtime",
    "std",
    "wasmtime-jit-icache-coherence",
];

/// The pinned Engine configuration: a 512 KiB Wasm stack, fuel and epochs.
const PINNED_ENGINE: PinnedEngineConfigV1 = PinnedEngineConfigV1 {
    max_wasm_stack: 524_288,
    consume_fuel: true,
    epoch_interruption: true,
};

// Short names for the outcomes of the table rows below.
const UNREACHABLE: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::Unreachable);
const MEMORY: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::MemoryOutOfBounds);
const TABLE: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::TableOutOfBounds);
const INDIRECT: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::IndirectCall);
const INTEGER: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::IntegerArithmetic);
const STACK: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::StackExhausted);
const OTHER: TrapOutcomeV1 = TrapOutcomeV1::Trap(ComponentTrapClassV1::Other);
const FUEL: TrapOutcomeV1 = TrapOutcomeV1::FuelExhausted;
const WATCHDOG: TrapOutcomeV1 = TrapOutcomeV1::WatchdogStop;

/// Every trap code of Wasmtime 49.0.2, in code order, with its outcome.
const PINNED_TRAP_TABLE: [(&str, TrapOutcomeV1); 50] = [
    ("StackOverflow", STACK),
    ("MemoryOutOfBounds", MEMORY),
    ("HeapMisaligned", MEMORY),
    ("TableOutOfBounds", TABLE),
    ("IndirectCallToNull", INDIRECT),
    ("BadSignature", INDIRECT),
    ("IntegerOverflow", INTEGER),
    ("IntegerDivisionByZero", INTEGER),
    ("BadConversionToInteger", INTEGER),
    ("UnreachableCodeReached", UNREACHABLE),
    ("Interrupt", WATCHDOG),
    ("OutOfFuel", FUEL),
    ("AtomicWaitNonSharedMemory", OTHER),
    ("NullReference", OTHER),
    ("ArrayOutOfBounds", MEMORY),
    ("AllocationTooLarge", OTHER),
    ("CastFailure", OTHER),
    ("CannotEnterComponent", OTHER),
    ("NoAsyncResult", OTHER),
    ("UnhandledTag", OTHER),
    ("ContinuationAlreadyConsumed", OTHER),
    ("DisabledOpcode", OTHER),
    ("AsyncDeadlock", OTHER),
    ("CannotLeaveComponent", OTHER),
    ("CannotBlockSyncTask", OTHER),
    ("InvalidChar", OTHER),
    ("DebugAssertStringEncodingFinished", OTHER),
    ("DebugAssertEqualCodeUnits", OTHER),
    ("DebugAssertPointerAligned", OTHER),
    ("DebugAssertUpperBitsUnset", OTHER),
    ("StringOutOfBounds", OTHER),
    ("ListOutOfBounds", OTHER),
    ("InvalidDiscriminant", OTHER),
    ("UnalignedPointer", OTHER),
    ("TaskCancelNotCancelled", OTHER),
    ("TaskCancelOrReturnTwice", OTHER),
    ("SubtaskCancelAfterTerminal", OTHER),
    ("TaskReturnInvalid", OTHER),
    ("WaitableSetDropHasWaiters", OTHER),
    ("SubtaskDropNotResolved", OTHER),
    ("ThreadNewIndirectInvalidType", OTHER),
    ("ThreadNewIndirectUninitialized", OTHER),
    ("BackpressureOverflow", OTHER),
    ("UnsupportedCallbackCode", OTHER),
    ("CannotResumeThread", OTHER),
    ("ConcurrentFutureStreamOp", OTHER),
    ("ReferenceCountOverflow", OTHER),
    ("StreamOpTooBig", OTHER),
    ("WaitableSyncAndAsync", OTHER),
    ("UncaughtException", OTHER),
];

/// The closed outcomes of ADR-061 revision 4 decision 6, for reading a name.
const CLOSED_OUTCOMES: [TrapOutcomeV1; 9] = [
    UNREACHABLE,
    MEMORY,
    TABLE,
    INDIRECT,
    INTEGER,
    STACK,
    OTHER,
    FUEL,
    WATCHDOG,
];

/// The runtime identity of the worker, built from the constants.
///
/// It equals the runtime `pos-plugin-host` derives from Wasmtime (a test
/// there proves it) and satisfies `PinnedComponentRuntimeV1::new`'s trap-table
/// validation (a test here proves it), so building it cannot fail.
#[must_use]
pub fn pinned_runtime_v1() -> PinnedComponentRuntimeV1 {
    PinnedComponentRuntimeV1 {
        wasmtime_version: PINNED_WASMTIME_VERSION.to_owned(),
        resolved_features: PINNED_RESOLVED_FEATURES.map(str::to_owned).to_vec(),
        engine: PINNED_ENGINE,
        trap_table: PINNED_TRAP_TABLE
            .map(|(trap_code, outcome)| TrapTableEntryV1 {
                trap_code: trap_code.to_owned(),
                outcome,
            })
            .to_vec(),
    }
}

impl TrapOutcomeV1 {
    /// The outcome with the closed outcome name `name`, if there is one.
    fn from_name(name: &str) -> Option<Self> {
        CLOSED_OUTCOMES
            .into_iter()
            .find(|outcome| outcome.name() == name)
    }
}

impl TrapTableEntryV1 {
    /// A classified row from the outcome name of ADR-061 revision 4 decision 6.
    ///
    /// The names are `unreachable`, `memory-out-of-bounds`,
    /// `table-out-of-bounds`, `indirect-call`, `integer-arithmetic`,
    /// `stack-exhausted`, `other`, `FuelExhausted` and
    /// `OperationalWatchdogStop`. It returns `None` for an unknown name or an
    /// outcome that the decision 6 table does not give `trap_code`.
    ///
    /// The conformance adapter (slice S2, #615) is the production consumer;
    /// until it lands only tests call this.
    #[must_use]
    pub fn from_adr_outcome(trap_code: &str, outcome_name: &str) -> Option<Self> {
        TrapOutcomeV1::from_name(outcome_name)
            .filter(|&outcome| super::adr_outcome(trap_code) == outcome)
            .map(|outcome| Self {
                trap_code: trap_code.to_owned(),
                outcome,
            })
    }
}

/// The execution profile digest of `ceilings` and `runtime`.
///
/// The digest excludes the mode (ADR-061 revision 7 decision 7), so none is
/// taken. It returns `None` when `ceilings` is outside its PMF1 V1 ranges.
///
/// The conformance adapter (slice S2, #615) computes `profile_digest` through
/// it; until it lands only tests call this.
#[must_use]
pub fn profile_digest_of(
    ceilings: CeilingValuesV1,
    runtime: PinnedComponentRuntimeV1,
) -> Option<[u8; 32]> {
    CommunityPluginCeilingsV1::new(ceilings)
        .ok()
        .and_then(|checked| {
            CommunityPluginExecutionProfileV1::new(
                CommunityPluginModeV1::Local,
                checked,
                Some(runtime),
            )
            .digest()
        })
}
