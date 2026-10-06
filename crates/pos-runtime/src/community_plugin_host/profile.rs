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

const MINIMA: DeterministicBudgetV1 = DeterministicBudgetV1::MINIMA;
const MAXIMA: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;

/// A live Execution Mode that runs community Plugin Components.
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
        let memory = (MINIMA.memory_bytes..=MAXIMA.memory_bytes).contains(&self.memory_bytes)
            && self.memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1);
        [
            (memory, ExecutionLimitV1::MemoryBytes),
            (self.fuel >= MINIMA.fuel, ExecutionLimitV1::Fuel),
            (
                self.host_calls <= MAXIMA.host_calls,
                ExecutionLimitV1::HostCalls,
            ),
            (
                self.event_bytes <= MAXIMA.event_bytes,
                ExecutionLimitV1::EventBytes,
            ),
            (
                self.log_bytes <= MAXIMA.log_bytes,
                ExecutionLimitV1::LogBytes,
            ),
        ]
        .into_iter()
        .find(|&(valid, _)| !valid)
        .map(|(_, limit)| limit)
    }
}

/// Validated host-owned ceilings for the five profile-limited members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPluginCeilingsV1 {
    values: CeilingValuesV1,
}

impl CommunityPluginCeilingsV1 {
    /// The provisional V1 host ceilings for both Local and Air-Gapped modes.
    ///
    /// Memory is 64 MiB (1,024 pages) and fuel is 10,000,000,000 units of
    /// pinned Wasmtime fuel; host calls, Event bytes and log bytes stay at
    /// their PMF1 V1 maxima. The values await an owner decision informed by
    /// the #539 budget measurements.
    pub const V1: Self = Self {
        values: CeilingValuesV1 {
            memory_bytes: 1_024 * WASM_PAGE_BYTES_V1,
            fuel: 10_000_000_000,
            host_calls: MAXIMA.host_calls,
            event_bytes: MAXIMA.event_bytes,
            log_bytes: MAXIMA.log_bytes,
        },
    };

    /// Validate operator ceilings against the PMF1 V1 member ranges.
    ///
    /// # Errors
    /// Returns `CeilingOutOfRange` for the first member, in budget order,
    /// that is outside its PMF1 V1 range, or a memory ceiling that is not a
    /// whole number of 65,536-byte pages.
    pub fn new(values: CeilingValuesV1) -> Result<Self, CommunityPluginProfileErrorV1> {
        values
            .first_out_of_range()
            .map_or(Ok(Self { values }), |limit| {
                Err(CommunityPluginProfileErrorV1::CeilingOutOfRange { limit })
            })
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
    /// stop, and every other code yields exactly one trap class.
    fn is_classified(&self) -> bool {
        let reserved = match self.trap_code.as_str() {
            "OutOfFuel" => Some(TrapOutcomeV1::FuelExhausted),
            "Interrupt" => Some(TrapOutcomeV1::WatchdogStop),
            _ => None,
        };
        reserved.map_or(matches!(self.outcome, TrapOutcomeV1::Trap(_)), |expected| {
            expected == self.outcome
        })
    }
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
    /// Before execution, #541 must require rows for `OutOfFuel`, `Interrupt`
    /// and every other trap code of the pinned version.
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
        duplicate.or(misclassified).map_or(
            Ok(Self {
                wasmtime_version,
                resolved_features,
                engine,
                trap_table,
            }),
            Err,
        )
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
/// `runtime` stays optional in this slice; #541 must require `Some` before
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
