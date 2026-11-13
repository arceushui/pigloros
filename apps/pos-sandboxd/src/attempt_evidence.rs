//! The typed resource evidence one attempt carries to its lifecycle
//! (ADR-069 R9 §4.3, §4.4 and §4.6).
//!
//! Evidence is collected in three phases, each before the next transition can
//! erase it:
//!
//! * [`ReleaseResources`]: after the cgroup is bound and before `ReleaseV1`,
//!   the unit's activation time (the anchor of the watchdog deadline `D`),
//!   the cgroup's baseline counters and its effective kernel limits;
//! * [`ReleaseOutcome`]: what the launcher barrier established: the accepted
//!   `ReadyV1`, the frozen KOE1 kernel observation, and the `ReleaseV1` sent;
//! * [`TerminalResources`]: after the payload exited and before teardown,
//!   the terminal counters, `/work` usage, the unit's result and the release
//!   of its pin.
//!
//! The requested configuration (RQE1's inputs) is the verified start itself.
//! Nothing here is encoded, digested or signed, and nothing classifies the
//! attempt: the record encoders and the classifier read these typed values.

use std::fs::File;

use pos_reference::sandbox_provider_protocol::ExecutionRelease;

use crate::{
    AttemptCgroupError, AttemptLimitEventSnapshot, EffectiveCgroupLimits, KernelObservation,
    KernelObservationError, ObservedUnit, SystemdTransientUnitTransportError,
    SystemdUnitResultError, SystemdUnitResultObservation, WorkUsage,
};

/// The pre-release evidence of one bound unit.
#[derive(Debug)]
pub struct ReleaseResources {
    activated_monotonic_ns: u64,
    baseline: AttemptLimitEventSnapshot,
    effective: EffectiveCgroupLimits,
}

impl ReleaseResources {
    pub(crate) const fn new(
        activated_monotonic_ns: u64,
        baseline: AttemptLimitEventSnapshot,
        effective: EffectiveCgroupLimits,
    ) -> Self {
        Self {
            activated_monotonic_ns,
            baseline,
            effective,
        }
    }

    /// The unit's `ActiveEnterTimestampMonotonic` in `CLOCK_MONOTONIC`
    /// nanoseconds; `D` is this plus the ELM1 watchdog.
    #[must_use]
    pub const fn activated_monotonic_ns(&self) -> u64 {
        self.activated_monotonic_ns
    }

    /// The limit-event counters captured before release (TME1 `baseline`).
    #[must_use]
    pub const fn baseline(&self) -> &AttemptLimitEventSnapshot {
        &self.baseline
    }

    /// The effective kernel limits of the bound cgroup.
    #[must_use]
    pub const fn effective(&self) -> &EffectiveCgroupLimits {
        &self.effective
    }
}

/// What the launcher barrier established, whether it released or not.
#[derive(Debug)]
pub struct ReleaseOutcome {
    ready1_digest: Option<[u8; 32]>,
    observed: Option<ObservedUnit>,
    release: Option<ExecutionRelease>,
}

impl ReleaseOutcome {
    pub(crate) const fn new(
        ready1_digest: Option<[u8; 32]>,
        observed: Option<ObservedUnit>,
        release: Option<ExecutionRelease>,
    ) -> Self {
        Self {
            ready1_digest,
            observed,
            release,
        }
    }

    /// The digest of the accepted `ReadyV1`; `None` when none was accepted.
    #[must_use]
    pub const fn ready1_digest(&self) -> Option<[u8; 32]> {
        self.ready1_digest
    }

    /// The kernel observation frozen after `ReadyV1`; `None` when none was
    /// made (KOE1 status 1 or 2).
    #[must_use]
    pub fn observation(&self) -> Option<&KernelObservation> {
        self.observed.as_ref().map(ObservedUnit::observation)
    }

    /// The `/work` handle the frozen observation opened, kept for the
    /// terminal `work-after` reading.
    #[must_use]
    pub fn work(&self) -> Option<&File> {
        self.observed.as_ref().and_then(ObservedUnit::work)
    }

    /// The `ReleaseV1` sent; its `observed_readback_digest` is the KOE1
    /// self-digest. `None` when the release was denied or never reached.
    #[must_use]
    pub const fn release(&self) -> Option<&ExecutionRelease> {
        self.release.as_ref()
    }
}

/// Why the unit's terminal result is missing.
#[derive(Debug, thiserror::Error)]
pub enum TerminalServiceError {
    /// The execution failed before a verified start reached the lifecycle,
    /// so no exact unit object is known to read.
    #[error("no verified start is known for the unit")]
    Unstarted,
    /// The result could not be read over the retained connection; the pin
    /// may be gone with it, so it is never read again elsewhere.
    #[error(transparent)]
    Read(#[from] SystemdUnitResultError),
}

/// The terminal evidence read after exit and before teardown.
#[derive(Debug)]
pub struct TerminalResources {
    terminal: Result<AttemptLimitEventSnapshot, AttemptCgroupError>,
    work_after: Option<Result<WorkUsage, KernelObservationError>>,
    service: Result<SystemdUnitResultObservation, TerminalServiceError>,
    unpinned: Result<(), SystemdTransientUnitTransportError>,
}

impl TerminalResources {
    pub(crate) const fn new(
        terminal: Result<AttemptLimitEventSnapshot, AttemptCgroupError>,
        work_after: Option<Result<WorkUsage, KernelObservationError>>,
        service: Result<SystemdUnitResultObservation, TerminalServiceError>,
        unpinned: Result<(), SystemdTransientUnitTransportError>,
    ) -> Self {
        Self {
            terminal,
            work_after,
            service,
            unpinned,
        }
    }

    /// The limit-event counters after exit (TME1 `terminal`).
    #[must_use]
    pub const fn terminal(&self) -> &Result<AttemptLimitEventSnapshot, AttemptCgroupError> {
        &self.terminal
    }

    /// `/work` after exit (TME1 `work-after`); `None` when no `/work` mount
    /// was observed.
    #[must_use]
    pub const fn work_after(&self) -> Option<&Result<WorkUsage, KernelObservationError>> {
        self.work_after.as_ref()
    }

    /// The unit's `Result`, `ExecMainCode` and `ExecMainStatus` (TME1
    /// `service`).
    #[must_use]
    pub const fn service(&self) -> &Result<SystemdUnitResultObservation, TerminalServiceError> {
        &self.service
    }

    /// Whether `UnrefUnit` released the unit's pin. A failure leaves the unit
    /// loaded, which the teardown's absence wait then reports.
    #[must_use]
    pub const fn unpinned(&self) -> &Result<(), SystemdTransientUnitTransportError> {
        &self.unpinned
    }
}

/// The resource evidence of one attempt that reached its unit start.
#[derive(Debug)]
pub struct ResourceEvidence {
    resources: Option<ReleaseResources>,
    release: ReleaseOutcome,
    terminal: Option<TerminalResources>,
}

impl ResourceEvidence {
    pub(crate) const fn new(resources: Option<ReleaseResources>, release: ReleaseOutcome) -> Self {
        Self {
            resources,
            release,
            terminal: None,
        }
    }

    /// The pre-release evidence; `None` when the execution failed before it
    /// was read.
    #[must_use]
    pub const fn resources(&self) -> Option<&ReleaseResources> {
        self.resources.as_ref()
    }

    /// What the launcher barrier established.
    #[must_use]
    pub const fn release(&self) -> &ReleaseOutcome {
        &self.release
    }

    /// The terminal evidence; `None` when no cgroup was bound, so nothing
    /// was pinned or measured.
    #[must_use]
    pub const fn terminal(&self) -> Option<&TerminalResources> {
        self.terminal.as_ref()
    }

    /// Record the terminal evidence, once, before teardown.
    pub(crate) fn conclude(&mut self, terminal: TerminalResources) {
        self.terminal = Some(terminal);
    }
}
