//! The host-owned community Plugin execution profile (ADR-061 revision 4).
//!
//! It is the ADR-024 runtime profile that ADR-061 revision 3 section 3.3
//! names as the authority for lowering the PMF1 V1 budget maxima. It does not
//! extend or replace the ADR-058 `ExecutionProfile` artifact: the
//! `ReproManifest` records this profile as the pinned Component-execution
//! input next to that artifact, whose ownership is unchanged.

use crate::composition::PluginExecutionModeV1;

use super::error::{CommunityPluginHostErrorV1, ComponentTrapClassV1};

/// WebAssembly page size; the memory ceiling is a whole number of pages.
pub const WASM_PAGE_BYTES_V1: u64 = 65_536;
/// PMF1 V1 maximum `memory_bytes` (4 GiB).
const MAX_MEMORY_BYTES: u64 = 4_294_967_296;
/// PMF1 V1 maximum `host_calls`.
const MAX_HOST_CALLS: u64 = 1_000_000;
/// PMF1 V1 maximum `event_bytes` (16 MiB).
const MAX_EVENT_BYTES: u64 = 16_777_216;
/// PMF1 V1 maximum `log_bytes` (64 calls of 256 bytes).
const MAX_LOG_BYTES: u64 = 16_384;

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

/// One `DeterministicBudgetV1` member.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionLimitV1 {
    /// `memory_bytes`.
    MemoryBytes,
    /// `fuel`.
    Fuel,
    /// `host_calls`.
    HostCalls,
    /// `event_count`.
    EventCount,
    /// `event_bytes`.
    EventBytes,
    /// `state_bytes`.
    StateBytes,
    /// `log_calls`.
    LogCalls,
    /// `log_bytes`.
    LogBytes,
}

/// A rejected community Plugin profile ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommunityPluginProfileErrorV1 {
    /// The ceiling is outside its PMF1 V1 member range or page multiple.
    #[error("community Plugin profile ceiling {limit:?} is out of range")]
    CeilingOutOfRange {
        /// The rejected member.
        limit: ExecutionLimitV1,
    },
}

/// Host-owned ceilings for the five profile-limited budget members.
///
/// `event_count`, `state_bytes` and `log_calls` are bounded by the WIT
/// ceilings instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityPluginCeilingsV1 {
    memory_bytes: u64,
    fuel: u64,
    host_calls: u64,
    event_bytes: u64,
    log_bytes: u64,
}

impl CommunityPluginCeilingsV1 {
    /// The V1 host ceilings for both Local and Air-Gapped modes.
    ///
    /// Memory is 64 MiB (1,024 pages) and fuel is 10,000,000,000 units of
    /// pinned Wasmtime fuel; host calls, Event bytes and log bytes stay at
    /// their PMF1 V1 maxima.
    pub const V1: Self = Self {
        memory_bytes: 1_024 * WASM_PAGE_BYTES_V1,
        fuel: 10_000_000_000,
        host_calls: MAX_HOST_CALLS,
        event_bytes: MAX_EVENT_BYTES,
        log_bytes: MAX_LOG_BYTES,
    };

    /// Validate operator ceilings against the PMF1 V1 member ranges.
    ///
    /// # Errors
    /// Returns `CeilingOutOfRange` for the first member, in budget order,
    /// that is outside its PMF1 V1 range, or a memory ceiling that is not a
    /// whole number of 65,536-byte pages.
    pub fn new(
        memory_bytes: u64,
        fuel: u64,
        host_calls: u64,
        event_bytes: u64,
        log_bytes: u64,
    ) -> Result<Self, CommunityPluginProfileErrorV1> {
        let checks = [
            (valid_memory(memory_bytes), ExecutionLimitV1::MemoryBytes),
            (fuel > 0, ExecutionLimitV1::Fuel),
            (host_calls <= MAX_HOST_CALLS, ExecutionLimitV1::HostCalls),
            (event_bytes <= MAX_EVENT_BYTES, ExecutionLimitV1::EventBytes),
            (log_bytes <= MAX_LOG_BYTES, ExecutionLimitV1::LogBytes),
        ];
        match checks.into_iter().find(|&(valid, _)| !valid) {
            Some((_, limit)) => Err(CommunityPluginProfileErrorV1::CeilingOutOfRange { limit }),
            None => Ok(Self {
                memory_bytes,
                fuel,
                host_calls,
                event_bytes,
                log_bytes,
            }),
        }
    }

    /// Linear memory ceiling in bytes.
    #[must_use]
    pub const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    /// Wasmtime fuel ceiling.
    #[must_use]
    pub const fn fuel(&self) -> u64 {
        self.fuel
    }

    /// Host import call ceiling.
    #[must_use]
    pub const fn host_calls(&self) -> u64 {
        self.host_calls
    }

    /// Total `EventDraft` byte ceiling.
    #[must_use]
    pub const fn event_bytes(&self) -> u64 {
        self.event_bytes
    }

    /// Total operational log byte ceiling.
    #[must_use]
    pub const fn log_bytes(&self) -> u64 {
        self.log_bytes
    }
}

/// A whole number of pages from one page to 4 GiB.
fn valid_memory(memory_bytes: u64) -> bool {
    (WASM_PAGE_BYTES_V1..=MAX_MEMORY_BYTES).contains(&memory_bytes)
        && memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1)
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
    #[must_use]
    pub const fn error(self) -> CommunityPluginHostErrorV1 {
        match self {
            Self::Trap(class) => CommunityPluginHostErrorV1::ComponentTrap { class },
            Self::FuelExhausted => CommunityPluginHostErrorV1::FuelExhausted,
            Self::WatchdogStop => CommunityPluginHostErrorV1::OperationalWatchdogStop,
        }
    }
}

/// One row of the pinned runtime's trap table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrapTableEntryV1 {
    /// The pinned runtime's trap code name, such as `UnreachableCodeReached`.
    pub trap_code: String,
    /// What the code yields.
    pub outcome: TrapOutcomeV1,
}

/// The pinned Component runtime identity a profile records (decision 2).
///
/// The Wasmtime pin and its compatibility evidence (#539) and the in-worker
/// engine (#541) populate it; a new pin is a new execution-profile version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedComponentRuntimeV1 {
    /// The exact pinned Wasmtime version.
    pub wasmtime_version: String,
    /// The resolved Wasmtime feature set, sorted.
    pub resolved_features: Vec<String>,
    /// The Engine `max_wasm_stack` in bytes.
    pub max_wasm_stack: u64,
    /// Whether the Engine meters fuel.
    pub consume_fuel: bool,
    /// Whether the Engine enables epoch interruption for the watchdog.
    pub epoch_interruption: bool,
    /// Every trap code of the pinned version and its outcome.
    pub trap_table: Vec<TrapTableEntryV1>,
}

/// The host-owned community Plugin execution profile for one live mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginExecutionProfileV1 {
    mode: CommunityPluginModeV1,
    ceilings: CommunityPluginCeilingsV1,
    runtime: Option<PinnedComponentRuntimeV1>,
}

impl CommunityPluginExecutionProfileV1 {
    /// A profile with `ceilings` and no recorded runtime identity yet.
    #[must_use]
    pub const fn new(mode: CommunityPluginModeV1, ceilings: CommunityPluginCeilingsV1) -> Self {
        Self {
            mode,
            ceilings,
            runtime: None,
        }
    }

    /// Local and Air-Gapped profiles with identical ceilings and runtime.
    ///
    /// Fixtures that prove Local and Air-Gapped parity use this pair, so the
    /// compatibility gate's identical-output requirement holds.
    #[must_use]
    pub fn parity_pair(
        ceilings: CommunityPluginCeilingsV1,
        runtime: Option<&PinnedComponentRuntimeV1>,
    ) -> [Self; 2] {
        [
            CommunityPluginModeV1::Local,
            CommunityPluginModeV1::AirGapped,
        ]
        .map(|mode| Self {
            mode,
            ceilings,
            runtime: runtime.cloned(),
        })
    }

    /// This profile with `runtime` recorded as its pinned runtime identity.
    #[must_use]
    pub fn with_runtime(mut self, runtime: PinnedComponentRuntimeV1) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Whether `other` carries identical ceilings and runtime identity.
    #[must_use]
    pub fn has_parity_with(&self, other: &Self) -> bool {
        self.ceilings == other.ceilings && self.runtime == other.runtime
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
