//! Bounded, unit-first process shutdown of an already bound attempt cgroup.

use std::time::Duration;

use tokio::time::{sleep_until, timeout_at, Instant};

use super::{
    AttemptCgroupEmptyBasis, AttemptCgroupEmptyObservation, AttemptCgroupError, BoundAttemptCgroup,
};
use crate::UnitHost;

const EMPTY_POLL: Duration = Duration::from_millis(10);

/// Absolute phase deadlines supplied by the trusted lifecycle controller.
///
/// These carry no default grace period and do not change the attempt's execution
/// limits. The controller must reserve time after the unit kill call for kernel
/// escalation and independent observation, within its overall cleanup budget.
#[derive(Clone, Copy, Debug)]
pub struct AttemptShutdownDeadlines {
    grace: Instant,
    unit_kill: Instant,
    overall: Instant,
}

impl AttemptShutdownDeadlines {
    /// Bound stop plus grace, the unit SIGKILL call, and final observation.
    ///
    /// # Errors
    /// Rejects deadlines that are not strictly increasing.
    pub fn new(
        grace: Instant,
        unit_kill: Instant,
        overall: Instant,
    ) -> Result<Self, AttemptShutdownError> {
        if grace >= unit_kill || unit_kill >= overall {
            return Err(AttemptShutdownError::InvalidDeadlines);
        }
        Ok(Self {
            grace,
            unit_kill,
            overall,
        })
    }
}

/// Failure to obtain process-emptiness evidence within a shutdown budget.
#[derive(Debug, thiserror::Error)]
pub enum AttemptShutdownError {
    /// A phase would leave no time for the following phase.
    #[error("attempt shutdown deadlines must be strictly increasing")]
    InvalidDeadlines,
    /// No timely process-emptiness observation was obtained.
    #[error("attempt process-shutdown deadline elapsed")]
    DeadlineElapsed,
    /// The exact retained cgroup could not be observed or escalated safely.
    #[error(transparent)]
    Cgroup(#[from] AttemptCgroupError),
}

impl BoundAttemptCgroup {
    /// Stop the bound unit, allow bounded grace, then escalate if necessary.
    ///
    /// The target unit comes only from this retained binding. The lifecycle
    /// controller must exclusively own that attempt identity throughout the
    /// operation. Stop/kill acknowledgements (including errors and timeouts)
    /// never establish emptiness: only the retained kernel observation can.
    /// A stalled manager kill cannot consume the reserved kernel-observation
    /// budget. Escalation sends unit-wide SIGKILL before descriptor-bound
    /// `cgroup.kill`, without addressing individual PIDs.
    ///
    /// A genuinely deleted original cgroup needs no further process signalling.
    /// Success proves only process emptiness at the observation time. It does
    /// not prove unit absence, prevent a later unit start, authorize unmount or
    /// intent deletion, reopen admission, or constitute terminal evidence.
    ///
    /// # Errors
    /// Rejects an expired grace budget before any command, an identity/read/kill
    /// failure, or lack of independent emptiness evidence before the deadline.
    pub async fn stop_processes<H: UnitHost + Sync>(
        &mut self,
        host: &H,
        deadlines: AttemptShutdownDeadlines,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptShutdownError> {
        if Instant::now() >= deadlines.grace {
            return Err(AttemptShutdownError::DeadlineElapsed);
        }
        match self.observe_before(deadlines.overall) {
            Ok(empty) if empty.basis() == AttemptCgroupEmptyBasis::Deleted => return Ok(empty),
            Ok(_) | Err(AttemptShutdownError::Cgroup(AttemptCgroupError::StillPopulated)) => {}
            Err(error) => return Err(error),
        }

        let unit_name = self.identity.unit_name.clone();
        let _stop = timeout_at(deadlines.grace, host.stop(unit_name.clone())).await;
        match self.wait_empty_before(deadlines.grace).await {
            Err(AttemptShutdownError::DeadlineElapsed) => {}
            result => return result,
        }

        if Instant::now() < deadlines.unit_kill {
            let _kill = timeout_at(deadlines.unit_kill, host.kill(unit_name)).await;
        }
        self.kill_all().map_err(AttemptShutdownError::Cgroup)?;
        self.wait_empty_before(deadlines.overall).await
    }

    fn observe_before(
        &mut self,
        deadline: Instant,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptShutdownError> {
        if Instant::now() >= deadline {
            return Err(AttemptShutdownError::DeadlineElapsed);
        }
        let observed = self.observe_empty().map_err(AttemptShutdownError::Cgroup);
        // Synchronous kernel reads must also finish within the original budget.
        if Instant::now() >= deadline {
            return Err(AttemptShutdownError::DeadlineElapsed);
        }
        observed
    }

    async fn wait_empty_before(
        &mut self,
        deadline: Instant,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptShutdownError> {
        loop {
            match self.observe_before(deadline) {
                Err(AttemptShutdownError::Cgroup(AttemptCgroupError::StillPopulated)) => {}
                result => return result,
            }
            sleep_until((Instant::now() + EMPTY_POLL).min(deadline)).await;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
