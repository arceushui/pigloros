//! The host-owned community Plugin execution profile (ADR-061 revision 4).
//!
//! It is the ADR-024 runtime profile that ADR-061 revision 3 section 3.3
//! names as the authority for lowering the PMF1 V1 budget maxima. It does not
//! extend or replace the ADR-058 `ExecutionProfile` artifact: the
//! `ReproManifest` records this profile as the pinned Component-execution
//! input next to that artifact, whose ownership is unchanged.

use std::collections::BTreeSet;

use pos_crypto::plugin_execution::{DeterministicBudgetV1, WASM_PAGE_BYTES_V1};

use crate::composition::PluginExecutionModeV1;

use super::error::{CommunityPluginHostErrorV1, ComponentTrapClassV1, TrapReproductionV1};

/// The `wasmtime::Trap` code that is the authoritative `FuelExhausted`.
const OUT_OF_FUEL_TRAP_CODE: &str = "OutOfFuel";
/// The `wasmtime::Trap` code that is the operational watchdog stop.
const INTERRUPT_TRAP_CODE: &str = "Interrupt";

/// A live Execution Mode that runs community Plugin Components.
///
/// It mirrors `PluginExecutionModeV1` without Replay, because Replay uses the
/// profile recorded in its `ReproManifest` and never a host profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityPluginModeV1 {
    /// ADR-024 Local Execution Mode.
    Local,
    /// ADR-024 Air-Gapped Execution Mode.
    AirGapped,
}

impl CommunityPluginModeV1 {
    /// The live mode of a composition, or `None` for Replay.
    ///
    /// Historical Replay uses the profile recorded in its `ReproManifest`,
    /// never the host's current profile.
    #[must_use]
    pub const fn from_execution_mode(mode: PluginExecutionModeV1) -> Option<Self> {
        match mode {
            PluginExecutionModeV1::Local => Some(Self::Local),
            PluginExecutionModeV1::AirGapped => Some(Self::AirGapped),
            PluginExecutionModeV1::Replay => None,
        }
    }
}

/// One `DeterministicBudgetV1` member that a host profile ceiling limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionLimitV1 {
    /// `memory_bytes`.
    MemoryBytes,
    /// `fuel`.
    Fuel,
    /// `host_calls`.
    HostCalls,
    /// `event_bytes`.
    EventBytes,
    /// `log_bytes`.
    LogBytes,
}

impl ExecutionLimitV1 {
    /// The exact PMF1 `DeterministicBudgetV1` member name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MemoryBytes => "memory_bytes",
            Self::Fuel => "fuel",
            Self::HostCalls => "host_calls",
            Self::EventBytes => "event_bytes",
            Self::LogBytes => "log_bytes",
        }
    }
}

/// A rejected community Plugin profile input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommunityPluginProfileErrorV1 {
    /// The ceiling is outside its PMF1 V1 member range or page multiple.
    #[error("community Plugin profile ceiling {} is out of range", .limit.name())]
    CeilingOutOfRange {
        /// The rejected member.
        limit: ExecutionLimitV1,
    },
    /// A pinned runtime trap code appears more than once.
    #[error("community Plugin trap table repeats code {index}")]
    DuplicateTrapCode {
        /// Position in the trap table.
        index: usize,
    },
    /// A trap code maps to an outcome the ADR-061 trap table forbids.
    #[error("community Plugin trap table misclassifies code {index}")]
    MisclassifiedTrapCode {
        /// Position in the trap table.
        index: usize,
    },
}

/// Raw host ceilings for the five profile-limited budget members.
///
/// `event_count`, `state_bytes` and `log_calls` are bounded by the WIT
/// ceilings in [`DeterministicBudgetV1::MAXIMA`] instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeilingValuesV1 {
    /// Linear memory bytes, a whole number of pages.
    pub memory_bytes: u64,
    /// Wasmtime fuel.
    pub fuel: u64,
    /// Host import calls.
    pub host_calls: u64,
    /// Total `EventDraft` bytes.
    pub event_bytes: u64,
    /// Total operational log bytes.
    pub log_bytes: u64,
}

impl CeilingValuesV1 {
    /// The first member, in budget order, outside its PMF1 V1 range.
    fn first_out_of_range(self) -> Option<ExecutionLimitV1> {
        let (minima, maxima) = (DeterministicBudgetV1::MINIMA, DeterministicBudgetV1::MAXIMA);
        let memory = (minima.memory_bytes..=maxima.memory_bytes).contains(&self.memory_bytes)
            && self.memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1);
        [
            (memory, ExecutionLimitV1::MemoryBytes),
            (self.fuel >= minima.fuel, ExecutionLimitV1::Fuel),
            (
                self.host_calls <= maxima.host_calls,
                ExecutionLimitV1::HostCalls,
            ),
            (
                self.event_bytes <= maxima.event_bytes,
                ExecutionLimitV1::EventBytes,
            ),
            (
                self.log_bytes <= maxima.log_bytes,
                ExecutionLimitV1::LogBytes,
            ),
        ]
        .into_iter()
        .find(|&(valid, _)| !valid)
        .map(|(_, limit)| limit)
    }

    /// Clamp `budget` member by member; a budget above a ceiling is clamped.
    ///
    /// This and [`Self::first_out_of_range`] are the one place that knows
    /// which members are profile-limited (`min(PMF1 budget, ceiling)`) and
    /// which are WIT-limited (`min(PMF1 budget, WIT maximum)`).
    fn clamp(self, budget: DeterministicBudgetV1) -> DeterministicBudgetV1 {
        let wit = DeterministicBudgetV1::MAXIMA;
        DeterministicBudgetV1 {
            memory_bytes: budget.memory_bytes.min(self.memory_bytes),
            fuel: budget.fuel.min(self.fuel),
            host_calls: budget.host_calls.min(self.host_calls),
            event_count: budget.event_count.min(wit.event_count),
            event_bytes: budget.event_bytes.min(self.event_bytes),
            state_bytes: budget.state_bytes.min(wit.state_bytes),
            log_calls: budget.log_calls.min(wit.log_calls),
            log_bytes: budget.log_bytes.min(self.log_bytes),
        }
    }
}

/// Validated host-owned ceilings for the five profile-limited members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPluginCeilingsV1 {
    values: CeilingValuesV1,
}

impl CommunityPluginCeilingsV1 {
    /// The V1 host ceilings for both Local and Air-Gapped modes.
    ///
    /// Memory is 64 MiB (1,024 pages) and fuel is 1,000,000,000 units of
    /// pinned Wasmtime fuel; host calls, Event bytes and log bytes stay at
    /// their PMF1 V1 maxima. The owner chose these on 2026-10-06 from the #539
    /// measurements, whose largest call (a 1 MiB reduce) used about 16.8
    /// million fuel and 2.3 MB of memory.
    pub const V1: Self = Self {
        values: CeilingValuesV1 {
            memory_bytes: 1_024 * WASM_PAGE_BYTES_V1,
            fuel: 1_000_000_000,
            host_calls: DeterministicBudgetV1::MAXIMA.host_calls,
            event_bytes: DeterministicBudgetV1::MAXIMA.event_bytes,
            log_bytes: DeterministicBudgetV1::MAXIMA.log_bytes,
        },
    };

    /// Validate operator ceilings against the PMF1 V1 member ranges.
    ///
    /// # Errors
    /// Returns `CeilingOutOfRange` for the first member, in budget order,
    /// that is outside its PMF1 V1 range, or a memory ceiling that is not a
    /// whole number of 65,536-byte pages.
    pub fn new(values: CeilingValuesV1) -> Result<Self, CommunityPluginProfileErrorV1> {
        if let Some(limit) = values.first_out_of_range() {
            return Err(CommunityPluginProfileErrorV1::CeilingOutOfRange { limit });
        }
        Ok(Self { values })
    }

    /// Clamp a PMF1 budget by these ceilings and the WIT ceilings.
    pub(super) fn clamp(&self, budget: DeterministicBudgetV1) -> DeterministicBudgetV1 {
        self.values.clamp(budget)
    }

    /// The validated ceiling values.
    #[must_use]
    pub const fn values(&self) -> CeilingValuesV1 {
        self.values
    }
}

/// What one pinned runtime trap code yields (ADR-061 revision 4 decision 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapOutcomeV1 {
    /// `ComponentTrap` with this canonical class.
    Trap(ComponentTrapClassV1),
    /// `OutOfFuel`: the authoritative `FuelExhausted`.
    FuelExhausted,
    /// `Interrupt`: the operational `OperationalWatchdogStop`.
    WatchdogStop,
}

impl TrapOutcomeV1 {
    /// The closed host error this outcome reports.
    ///
    /// A trap is `Unverified`: only conformance establishes reproduction.
    #[must_use]
    pub const fn error(self) -> CommunityPluginHostErrorV1 {
        match self {
            Self::Trap(class) => CommunityPluginHostErrorV1::ComponentTrap {
                class,
                reproduction: TrapReproductionV1::Unverified,
            },
            Self::FuelExhausted => CommunityPluginHostErrorV1::FuelExhausted,
            Self::WatchdogStop => CommunityPluginHostErrorV1::OperationalWatchdogStop,
        }
    }
}

/// One row of the pinned runtime's trap table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrapTableEntryV1 {
    /// The pinned `wasmtime::Trap` code name, such as `UnreachableCodeReached`.
    pub trap_code: String,
    /// What the code yields.
    pub outcome: TrapOutcomeV1,
}

impl TrapTableEntryV1 {
    /// Whether this row follows the ADR-061 trap table.
    ///
    /// `OutOfFuel` yields `FuelExhausted`, `Interrupt` yields the watchdog
    /// stop, every code named in decision 6 yields its ADR class, and every
    /// other code yields `other`.
    fn is_classified(&self) -> bool {
        adr_outcome(&self.trap_code) == self.outcome
    }
}

/// The ADR-061 revision 4 decision 6 outcome of one `wasmtime::Trap` code.
///
/// A listed code that the pinned version lacks is simply absent from its
/// table; an unlisted code is `other`.
fn adr_outcome(trap_code: &str) -> TrapOutcomeV1 {
    // Only `OutOfFuel` and `Interrupt` have named constants: they are the two
    // codes with a bespoke outcome that the pinned-runtime docs and #541
    // refer to. Every other code is a row of the decision 6 class table, which
    // is read here as literals.
    let class = match trap_code {
        OUT_OF_FUEL_TRAP_CODE => return TrapOutcomeV1::FuelExhausted,
        INTERRUPT_TRAP_CODE => return TrapOutcomeV1::WatchdogStop,
        "UnreachableCodeReached" => ComponentTrapClassV1::Unreachable,
        "MemoryOutOfBounds" | "HeapMisaligned" | "ArrayOutOfBounds" => {
            ComponentTrapClassV1::MemoryOutOfBounds
        }
        "TableOutOfBounds" => ComponentTrapClassV1::TableOutOfBounds,
        "IndirectCallToNull" | "BadSignature" => ComponentTrapClassV1::IndirectCall,
        "IntegerOverflow" | "IntegerDivisionByZero" | "BadConversionToInteger" => {
            ComponentTrapClassV1::IntegerArithmetic
        }
        "StackOverflow" => ComponentTrapClassV1::StackExhausted,
        _ => ComponentTrapClassV1::Other,
    };
    TrapOutcomeV1::Trap(class)
}

/// The pinned Engine configuration a profile records (decision 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedEngineConfigV1 {
    /// The Engine `max_wasm_stack` in bytes.
    pub max_wasm_stack: u64,
    /// Whether the Engine meters fuel.
    pub consume_fuel: bool,
    /// Whether the Engine enables epoch interruption for the watchdog.
    pub epoch_interruption: bool,
}

/// The pinned Component runtime identity a profile records (decision 2).
///
/// The Wasmtime pin (#539) and the in-worker engine (#541) populate it; a
/// new pin is a new execution-profile version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedComponentRuntimeV1 {
    wasmtime_version: String,
    resolved_features: Vec<String>,
    engine: PinnedEngineConfigV1,
    trap_table: Vec<TrapTableEntryV1>,
}

impl PinnedComponentRuntimeV1 {
    /// Record one pinned runtime identity with a validated trap table.
    ///
    /// The in-worker engine (`pos-plugin-host`) executes only under a
    /// profile whose runtime equals its own pinned runtime, whose table has a
    /// row for `OutOfFuel`, `Interrupt` and every other pinned trap code.
    ///
    /// # Errors
    /// Returns `DuplicateTrapCode` for the first repeated trap code, then
    /// `MisclassifiedTrapCode` for the first code whose outcome breaks the
    /// ADR-061 table: `OutOfFuel` must yield `FuelExhausted`, `Interrupt`
    /// the watchdog stop, and every other code one trap class.
    pub fn new(
        wasmtime_version: String,
        resolved_features: Vec<String>,
        engine: PinnedEngineConfigV1,
        trap_table: Vec<TrapTableEntryV1>,
    ) -> Result<Self, CommunityPluginProfileErrorV1> {
        let duplicate = first_duplicate(&trap_table)
            .map(|index| CommunityPluginProfileErrorV1::DuplicateTrapCode { index });
        let misclassified = trap_table
            .iter()
            .position(|entry| !entry.is_classified())
            .map(|index| CommunityPluginProfileErrorV1::MisclassifiedTrapCode { index });
        if let Some(error) = duplicate.or(misclassified) {
            return Err(error);
        }
        Ok(Self {
            wasmtime_version,
            resolved_features,
            engine,
            trap_table,
        })
    }

    /// The exact pinned Wasmtime version.
    #[must_use]
    pub fn wasmtime_version(&self) -> &str {
        &self.wasmtime_version
    }

    /// The resolved Wasmtime feature set.
    #[must_use]
    pub fn resolved_features(&self) -> &[String] {
        &self.resolved_features
    }

    /// The pinned Engine configuration.
    #[must_use]
    pub const fn engine(&self) -> PinnedEngineConfigV1 {
        self.engine
    }

    /// Every trap code of the pinned version and its outcome.
    #[must_use]
    pub fn trap_table(&self) -> &[TrapTableEntryV1] {
        &self.trap_table
    }
}

/// The position of the first trap code that an earlier row already names.
fn first_duplicate(trap_table: &[TrapTableEntryV1]) -> Option<usize> {
    let mut seen = BTreeSet::new();
    trap_table
        .iter()
        .position(|entry| !seen.insert(entry.trap_code.as_str()))
}

/// The host-owned community Plugin execution profile for one live mode.
///
/// `runtime` is optional here; the in-worker engine requires it before
/// any Component executes under the profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginExecutionProfileV1 {
    mode: CommunityPluginModeV1,
    ceilings: CommunityPluginCeilingsV1,
    runtime: Option<PinnedComponentRuntimeV1>,
}

impl CommunityPluginExecutionProfileV1 {
    /// A profile with `ceilings` and its pinned runtime identity, if recorded.
    #[must_use]
    pub const fn new(
        mode: CommunityPluginModeV1,
        ceilings: CommunityPluginCeilingsV1,
        runtime: Option<PinnedComponentRuntimeV1>,
    ) -> Self {
        Self {
            mode,
            ceilings,
            runtime,
        }
    }

    /// Local and Air-Gapped profiles with identical ceilings and runtime.
    ///
    /// Fixtures that prove Local and Air-Gapped parity use this pair, so the
    /// compatibility gate's identical-output requirement holds (decision 7).
    #[must_use]
    pub fn parity_pair(
        ceilings: CommunityPluginCeilingsV1,
        runtime: Option<&PinnedComponentRuntimeV1>,
    ) -> [Self; 2] {
        [
            CommunityPluginModeV1::Local,
            CommunityPluginModeV1::AirGapped,
        ]
        .map(|mode| Self::new(mode, ceilings, runtime.cloned()))
    }

    /// The live mode this profile applies to.
    #[must_use]
    pub const fn mode(&self) -> CommunityPluginModeV1 {
        self.mode
    }

    /// The host-owned ceilings.
    #[must_use]
    pub const fn ceilings(&self) -> CommunityPluginCeilingsV1 {
        self.ceilings
    }

    /// The recorded pinned runtime identity, once a later slice records it.
    #[must_use]
    pub const fn runtime(&self) -> Option<&PinnedComponentRuntimeV1> {
        self.runtime.as_ref()
    }
}
