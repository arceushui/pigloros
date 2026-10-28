//! Unit-first shutdown, failed-state release and independent absence observations.

use tokio::time::{timeout_at, Instant};

use super::{
    unit_absence::{wait_with_proxy, NO_SUCH_UNIT},
    ManagerProxy, SystemdAttemptUnitAbsenceObservation, SystemdTransientUnitTransport,
    SystemdTransientUnitTransportError, TransientServiceUnitName,
};
use crate::{
    AttemptCgroupEmptyObservation, AttemptShutdownDeadlines, AttemptShutdownError,
    BoundAttemptCgroup,
};

/// Fresh observations of an unloaded unit and its retained process-empty cgroup.
///
/// The lifecycle controller must exclusively own the attempt throughout teardown.
/// These observations do not fence a later start or establish namespace, mount,
/// device, directory or durable-intent absence. They do not authorize unmount,
/// intent deletion, cleanup success or admission reopening.
#[derive(Debug, Eq, PartialEq)]
pub struct SystemdAttemptUnitTeardownObservation {
    unit_absence: SystemdAttemptUnitAbsenceObservation,
    cgroup_empty: AttemptCgroupEmptyObservation,
}

impl SystemdAttemptUnitTeardownObservation {
    /// Return the exact-name manager absence observed after process shutdown.
    #[must_use]
    pub const fn unit_absence(&self) -> &SystemdAttemptUnitAbsenceObservation {
        &self.unit_absence
    }

    /// Return the retained cgroup observation refreshed after manager absence.
    #[must_use]
    pub const fn cgroup_empty(&self) -> &AttemptCgroupEmptyObservation {
        &self.cgroup_empty
    }
}

/// Failure to obtain both unit and process observations within the original budget.
#[derive(Debug, thiserror::Error)]
pub enum SystemdAttemptUnitTeardownError {
    /// Process shutdown leaves no reserved time for manager absence observation.
    #[error("attempt process shutdown must end before the unit teardown deadline")]
    InvalidDeadlines,
    /// The final absolute deadline elapsed before both observations were accepted.
    #[error("attempt unit teardown deadline elapsed")]
    DeadlineElapsed,
    /// The retained cgroup could not be safely shut down or observed.
    #[error(transparent)]
    Shutdown(#[from] AttemptShutdownError),
    /// The exact-name systemd absence operation failed.
    #[error(transparent)]
    Transport(#[from] SystemdTransientUnitTransportError),
    /// The manager rejected clearing this exact unit's failed state.
    #[error("failed to reset the exact attempt unit's failed state")]
    ResetFailed(#[source] zbus::Error),
}

impl SystemdTransientUnitTransport {
    /// Stop the retained attempt's processes and observe its unit unloaded.
    ///
    /// The unit name comes only from `cgroup`. Process shutdown uses the existing
    /// stop/grace/escalation path, whose overall deadline must precede `deadline`.
    /// Only after process emptiness does the operation send `ResetFailedUnit` to
    /// that name, allowing a failed transient service to be garbage collected.
    /// A successful reset or its exact `NoSuchUnit` error is only a command
    /// observation: a fresh `GetUnit` must independently prove absence. Finally,
    /// the retained cgroup identity and emptiness are checked again.
    ///
    /// The controller must retain exclusive attempt ownership and capture all
    /// required terminal systemd state before calling: unloading loses that state.
    /// One absolute final deadline covers every phase, including the final kernel
    /// read and acceptance check. Dropping this future does not complete teardown;
    /// the controller must retain ownership and reconcile the interrupted attempt.
    ///
    /// # Errors
    /// Rejects invalid or expired budgets, unsafe process observations, reset
    /// failures other than the exact missing-unit error, and failure to obtain
    /// fresh unit and cgroup observations strictly before the final deadline.
    pub async fn stop_attempt_unit(
        &self,
        cgroup: &mut BoundAttemptCgroup,
        shutdown: AttemptShutdownDeadlines,
        deadline: Instant,
    ) -> Result<SystemdAttemptUnitTeardownObservation, SystemdAttemptUnitTeardownError> {
        if shutdown.overall() >= deadline {
            return Err(SystemdAttemptUnitTeardownError::InvalidDeadlines);
        }
        if Instant::now() >= deadline {
            return Err(SystemdAttemptUnitTeardownError::DeadlineElapsed);
        }
        let observed = timeout_at(deadline, async {
            match cgroup.stop_processes(self, shutdown).await {
                Err(error) => Err(SystemdAttemptUnitTeardownError::Shutdown(error)),
                Ok(stopped) => {
                    let name = stopped.unit_name().clone();
                    remove_with_proxy(ManagerProxy::new(&self.connection).await, name, deadline)
                        .await
                        .and_then(|unit_absence| {
                            cgroup
                                .observe_empty()
                                .map(|cgroup_empty| SystemdAttemptUnitTeardownObservation {
                                    unit_absence,
                                    cgroup_empty,
                                })
                                .map_err(AttemptShutdownError::Cgroup)
                                .map_err(SystemdAttemptUnitTeardownError::Shutdown)
                        })
                }
            }
        })
        .await
        .unwrap_or(Err(SystemdAttemptUnitTeardownError::DeadlineElapsed));
        if Instant::now() >= deadline {
            return Err(SystemdAttemptUnitTeardownError::DeadlineElapsed);
        }
        observed
    }
}

async fn remove_with_proxy(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
    name: TransientServiceUnitName,
    deadline: Instant,
) -> Result<SystemdAttemptUnitAbsenceObservation, SystemdAttemptUnitTeardownError> {
    let proxy = match proxy {
        Ok(proxy) => proxy,
        Err(error) => {
            return Err(SystemdAttemptUnitTeardownError::Transport(
                SystemdTransientUnitTransportError::Proxy(error),
            ));
        }
    };
    let reset = match proxy.reset_failed_unit(name.as_str().to_owned()).await {
        Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == NO_SUCH_UNIT => Ok(()),
        result => result,
    };
    if let Err(error) = reset {
        return Err(SystemdAttemptUnitTeardownError::ResetFailed(error));
    }
    if Instant::now() >= deadline {
        return Err(SystemdAttemptUnitTeardownError::DeadlineElapsed);
    }
    let observed = wait_with_proxy(Ok(proxy), name).await.map_err(Into::into);
    observed
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
