//! Unit-first shutdown, failed-state release and independent absence observations.

use tokio::time::{timeout_at, Instant};

use zbus::{proxy::CacheProperties, OwnedObjectPath};
use zbus_systemd::systemd1::{ServiceProxy, UnitProxy};

use super::{
    unit_absence::{wait_with_proxy, NO_SUCH_UNIT},
    ManagerProxy, SystemdAttemptUnitAbsenceObservation, SystemdAttemptUnitObservation,
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, TransientServiceUnitName,
};
use crate::{
    AttemptCgroupEmptyObservation, AttemptCgroupError, AttemptShutdownDeadlines,
    AttemptShutdownError, BoundAttemptCgroup, CgroupRoot,
};

/// Fresh observations of an unloaded unit and its retained process-empty cgroup.
///
/// The lifecycle controller must exclusively own the attempt throughout teardown.
/// These observations do not fence a later start or establish namespace, mount,
/// device, directory or durable-intent absence. Alone they authorize no unmount,
/// cleanup success or admission reopening; they are the unit step consumed by
/// [`crate::PreparedAttemptDirectory::finish_terminal_cleanup`].
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

impl SystemdTransientUnitTransport {
    /// Stop a listed attempt unit that no start of this runtime bound.
    ///
    /// Restart reconciliation calls this for a previous runtime's unit whose
    /// name and `AttemptId` match a committed intent. Its cgroup is bound from
    /// the listed object path exactly as for a verified start: the manager's
    /// unit-to-cgroup mapping is checked in both directions around the kernel
    /// open. The unit is then stopped, emptied and removed as by
    /// [`Self::stop_attempt_unit`] with the same deadlines.
    ///
    /// A unit whose `ControlGroup` is empty has no cgroup to bind. By the
    /// owner's reading of ADR-087 §3 (owner decision A, 2026-11-10), such a
    /// unit is proven empty when its `ActiveState` is `inactive` or `failed`:
    /// systemd removes a unit's cgroup only once it is empty. A failed unit's
    /// state is then cleared with `ResetFailedUnit`, and a fresh `GetUnit`
    /// must observe the unit absent. The unit must still be the listed object,
    /// and its `ControlGroup` is read again after its state.
    ///
    /// # Errors
    /// A unit, cgroup or binding that cannot be verified, including a unit
    /// without a cgroup in any other state, is a
    /// [`SystemdAttemptUnitTeardownError::Transport`] failure; nothing is
    /// stopped. Teardown failures are returned as they occur.
    pub(crate) async fn stop_listed_unit(
        &self,
        unit: &SystemdAttemptUnitObservation,
        shutdown: AttemptShutdownDeadlines,
        deadline: Instant,
    ) -> Result<(), SystemdAttemptUnitTeardownError> {
        let stopped = self
            .stop_listed_with_root(
                unit.unit_name(),
                unit.unit_object_path(),
                CgroupRoot::system(),
                (shutdown, deadline),
            )
            .await;
        stopped
    }

    async fn stop_listed_with_root(
        &self,
        unit_name: &TransientServiceUnitName,
        unit_path: &OwnedObjectPath,
        root: Result<CgroupRoot, AttemptCgroupError>,
        (shutdown, deadline): (AttemptShutdownDeadlines, Instant),
    ) -> Result<(), SystemdAttemptUnitTeardownError> {
        let listed = self.listed_control_group(unit_path).await;
        match listed {
            Ok(cgroup) if cgroup.is_empty() => {
                return self.remove_cgroupless(unit_name, unit_path, deadline).await;
            }
            Ok(_) => {}
            Err(error) => return Err(SystemdAttemptUnitTeardownError::Transport(error)),
        }
        let bound = match root {
            Ok(root) => self.bind_unit_cgroup(unit_name, unit_path, root).await,
            Err(error) => Err(error.into()),
        };
        let mut cgroup = match bound {
            Ok(cgroup) => cgroup,
            Err(error) => return Err(SystemdAttemptUnitTeardownError::Transport(error)),
        };
        let stopped = self
            .stop_attempt_unit(&mut cgroup, shutdown, deadline)
            .await
            .map(drop);
        stopped
    }
}

impl SystemdTransientUnitTransport {
    /// The listed object's `ControlGroup`, read fresh from the manager.
    async fn listed_control_group(
        &self,
        unit_path: &OwnedObjectPath,
    ) -> Result<String, SystemdTransientUnitTransportError> {
        let service = ServiceProxy::builder(&self.connection)
            .path(unit_path.clone())
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
        let cgroup = service.control_group().await;
        cgroup.map_err(SystemdTransientUnitTransportError::CgroupReadback)
    }

    /// Remove a listed unit without a cgroup when it is inactive or failed
    /// (owner decision A): reset a failed unit, then observe it absent.
    async fn remove_cgroupless(
        &self,
        unit_name: &TransientServiceUnitName,
        unit_path: &OwnedObjectPath,
        deadline: Instant,
    ) -> Result<(), SystemdAttemptUnitTeardownError> {
        let failed = self.cgroupless_failed(unit_name, unit_path).await;
        let proxy = ManagerProxy::new(&self.connection).await;
        let removed = match failed {
            Ok(true) => remove_with_proxy(proxy, unit_name.clone(), deadline).await,
            Ok(false) => wait_with_proxy(proxy, unit_name.clone())
                .await
                .map_err(SystemdAttemptUnitTeardownError::Transport),
            Err(error) => Err(SystemdAttemptUnitTeardownError::Transport(error)),
        };
        removed.map(drop)
    }

    /// Whether the listed unit without a cgroup is failed (`true`) or
    /// inactive (`false`); any other state, another object or a cgroup that
    /// appeared is refused.
    async fn cgroupless_failed(
        &self,
        unit_name: &TransientServiceUnitName,
        unit_path: &OwnedObjectPath,
    ) -> Result<bool, SystemdTransientUnitTransportError> {
        let current = self.unit_path_of(unit_name).await?;
        if current != *unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        let unit = UnitProxy::builder(&self.connection)
            .path(unit_path.clone())
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
        let state = unit.active_state().await.map_err(|source| {
            SystemdTransientUnitTransportError::PropertyReadback {
                property: "ActiveState",
                source: Box::new(source),
            }
        })?;
        let failed = match state.as_str() {
            "failed" => true,
            "inactive" => false,
            _ => return Err(SystemdTransientUnitTransportError::CgrouplessUnitActive),
        };
        // A unit that started meanwhile has a cgroup again.
        let cgroup = self.listed_control_group(unit_path).await?;
        cgroup
            .is_empty()
            .then_some(failed)
            .ok_or(SystemdTransientUnitTransportError::CgroupUnitMismatch)
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
#[cfg(test)]
pub use tests::cases::{
    Fixture as TeardownFixture, ManagerCalls as TeardownManagerCalls, Reset as TeardownReset,
    Stop as TeardownStop,
};
