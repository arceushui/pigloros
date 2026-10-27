//! Bounded, unit-first process shutdown of an already bound attempt cgroup.

use std::time::Duration;

use rustix::io::Errno;
use tokio::time::{sleep, timeout_at, Instant};

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
    /// budget. Within that budget, escalation requests unit-wide SIGKILL before
    /// descriptor-bound `cgroup.kill`, without addressing individual PIDs.
    /// If scheduling misses the unit-kill cutoff, kernel killing is still
    /// requested as a fail-safe, but the operation returns a deadline failure.
    /// Later emptiness cannot repair a missed phase or overall deadline.
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
        drop(timeout_at(deadlines.grace, host.stop(unit_name.clone())).await);
        match self.wait_empty_before(deadlines.grace).await {
            Err(AttemptShutdownError::DeadlineElapsed) => {}
            result => return result,
        }

        let unit_kill_started = Instant::now() < deadlines.unit_kill;
        if unit_kill_started {
            drop(timeout_at(deadlines.unit_kill, host.kill(unit_name)).await);
        }
        let killed = self.kill_all();
        if !unit_kill_started {
            return Err(AttemptShutdownError::DeadlineElapsed);
        }
        match killed {
            Ok(()) => self.wait_empty_before(deadlines.overall).await,
            // A manager kill may have removed the original cgroup. A missing
            // pathname alone is insufficient; retain the exact deletion check.
            Err(AttemptCgroupError::KillTargetMissing) => self.observe_before(deadlines.overall),
            Err(AttemptCgroupError::KillOpen(Errno::NOENT)) => {
                self.observe_deleted_after_missing_control(deadlines.overall)
            }
            Err(error) => Err(AttemptShutdownError::Cgroup(error)),
        }
    }

    fn observe_deleted_after_missing_control(
        &mut self,
        deadline: Instant,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptShutdownError> {
        // Deletion may race the identity check and control-file open. Preserve
        // the command failure unless timely original-inode deletion is proven.
        match self.observe_before(deadline) {
            Ok(empty) if empty.basis() == AttemptCgroupEmptyBasis::Deleted => Ok(empty),
            Err(AttemptShutdownError::DeadlineElapsed) => {
                Err(AttemptShutdownError::DeadlineElapsed)
            }
            _ => Err(AttemptShutdownError::Cgroup(AttemptCgroupError::KillOpen(
                Errno::NOENT,
            ))),
        }
    }

    fn observe_before(
        &mut self,
        deadline: Instant,
    ) -> Result<AttemptCgroupEmptyObservation, AttemptShutdownError> {
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
            // Either timer wakes the probe; its original deadline still gates
            // the next observation, including when the poll ends late.
            let _wake = timeout_at(deadline, sleep(EMPTY_POLL)).await;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
