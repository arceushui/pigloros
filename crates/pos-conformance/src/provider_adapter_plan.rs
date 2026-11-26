//! The adapter each provider conformance case runs (ADR-069 section 9, #216).
//!
//! A case's adapter is the one static `/adapter` of the evidence image, whose
//! behaviour the signed SIM1 argument vector selects: `MODE` or `MODE BOUND`.
//! This table is the single source of those vectors. A limit case runs its
//! adapter past a ceiling that the case's attempt is built with, so each bound
//! is derived from that ceiling here, and no bound can fall to or below it.
//!
//! The ceilings are the conformance suite's own: no provider crate defines a
//! fixed limit set (the effective limit of an attempt is the minimum of the
//! broker caps, the launch policy and the attempt's own budget, ADR-069
//! section 4), so the guest binding builds each attempt with the ceiling named
//! here. `pos-conformance` has no provider dependency, so the values are
//! constants of this crate and a test asserts every bound is above its ceiling.

use crate::ProviderConformanceCase;

/// How far past its ceiling a limit case runs its adapter.
pub const OVERSHOOT: u64 = 2;
/// The attempt memory ceiling in bytes (ELM1 limit 0, the attempt budget).
pub const MEMORY_CEILING_BYTES: u64 = 64 << 20;
/// The attempt task ceiling (ELM1 limit 2, `pids.max`; a broker and launch cap).
pub const TASK_CEILING: u64 = 64;
/// The attempt watchdog in milliseconds (ELM1 limit 4).
pub const WATCHDOG_CEILING_MS: u64 = 5_000;
/// The attempt output ceiling in bytes (ELM1 limit 8).
pub const OUTPUT_CEILING_BYTES: u64 = 1 << 20;
/// The `/work` capacity in bytes (ELM1 limit 9).
pub const WORK_CEILING_BYTES: u64 = 16 << 20;

/// The argument vector of one case's adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterPlan {
    /// The adapter mode id.
    pub mode: &'static str,
    /// The decimal bound, for the modes that take one.
    pub bound: Option<u64>,
}

impl AdapterPlan {
    /// The signed argument vector: the mode, then the bound if there is one.
    #[must_use]
    pub fn arguments(self) -> Vec<String> {
        std::iter::once(self.mode.to_owned())
            .chain(self.bound.map(|bound| bound.to_string()))
            .collect()
    }
}

const fn plain(mode: &'static str) -> AdapterPlan {
    AdapterPlan { mode, bound: None }
}

const fn past(mode: &'static str, ceiling: u64) -> AdapterPlan {
    AdapterPlan {
        mode,
        bound: Some(ceiling * OVERSHOOT),
    }
}

impl ProviderConformanceCase {
    /// The adapter mode and bound the case runs.
    ///
    /// The cases that act on a running attempt (cancel, revoke, broker crash)
    /// run the idle mode for twice the watchdog, so only the case's own act
    /// ends the attempt before the watchdog would.
    #[must_use]
    pub const fn adapter_plan(self) -> AdapterPlan {
        match self {
            Self::FilesystemEscape
            | Self::ReadOnlyRootWrite
            | Self::NetworkEscape
            | Self::ForeignSignals
            | Self::OrphanedChild
            | Self::AdapterCrash
            | Self::MalformedOutput => plain(self.id()),
            Self::WorkAreaExhaustion => past(self.id(), WORK_CEILING_BYTES),
            Self::TaskExhaustion => past(self.id(), TASK_CEILING),
            Self::MemoryExhaustion => past(self.id(), MEMORY_CEILING_BYTES),
            Self::WatchdogExpiry => past(self.id(), WATCHDOG_CEILING_MS),
            Self::OversizedOutput => past(self.id(), OUTPUT_CEILING_BYTES),
            Self::CancelWhileRunning | Self::RevokedWhileRunning | Self::BrokerCrashRecovery => {
                past("idle", WATCHDOG_CEILING_MS)
            }
            Self::CancelBeforeRelease
            | Self::RevokedBeforeAdmission
            | Self::MissingHostFeature
            | Self::ConcurrentAttempts => plain("honest"),
        }
    }

    /// The ceiling the case's adapter bound runs past, if it probes one.
    #[must_use]
    pub const fn probed_ceiling(self) -> Option<u64> {
        match self {
            Self::WorkAreaExhaustion => Some(WORK_CEILING_BYTES),
            Self::TaskExhaustion => Some(TASK_CEILING),
            Self::MemoryExhaustion => Some(MEMORY_CEILING_BYTES),
            Self::WatchdogExpiry
            | Self::CancelWhileRunning
            | Self::RevokedWhileRunning
            | Self::BrokerCrashRecovery => Some(WATCHDOG_CEILING_MS),
            Self::OversizedOutput => Some(OUTPUT_CEILING_BYTES),
            _ => None,
        }
    }
}
