//! Bounded exact-name manager readback of an unloaded attempt unit.

use std::time::Duration;

use tokio::time::{sleep, timeout_at, Instant};

use super::{
    ManagerProxy, SystemdTransientUnitTransport, SystemdTransientUnitTransportError,
    TransientServiceUnitName,
};

const NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";
const UNIT_POLL: Duration = Duration::from_millis(10);

type AbsenceResult =
    Result<SystemdAttemptUnitAbsenceObservation, SystemdTransientUnitTransportError>;

/// The manager reported no loaded unit under this exact attempt name.
///
/// This is a point-in-time observation, not a fence against later starts or
/// evidence of cgroup, namespace, mount, device or directory absence. It cannot
/// authorize unmount, intent deletion, cleanup success or admission reopening.
/// The lifecycle controller must retain exclusive ownership of the attempt and
/// independently establish every other cleanup condition.
#[derive(Debug, Eq, PartialEq)]
pub struct SystemdAttemptUnitAbsenceObservation {
    unit_name: TransientServiceUnitName,
}

impl SystemdAttemptUnitAbsenceObservation {
    /// The canonical attempt name used by the exact `GetUnit` query.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }
}

impl SystemdTransientUnitTransport {
    /// Wait for the exact attempt unit to be unloaded before `deadline`.
    ///
    /// Only `GetUnit`'s exact `org.freedesktop.systemd1.NoSuchUnit` error is
    /// absence. A loaded object, including an inactive or failed unit, keeps
    /// waiting. No unit is loaded or changed, and an earlier absence is never
    /// cached. The original absolute deadline bounds proxy setup, every query
    /// and every poll, with a strict completion-time check before returning.
    ///
    /// # Errors
    /// Rejects an expired budget or a unit that stays loaded past the deadline.
    /// Propagates proxy and all other query failures, including access denial,
    /// unknown objects, missing bus owners and transport errors. Their text
    /// never substitutes for the exact systemd error name.
    pub async fn wait_for_attempt_unit_absence(
        &self,
        unit_name: TransientServiceUnitName,
        deadline: Instant,
    ) -> AbsenceResult {
        if Instant::now() >= deadline {
            return Err(SystemdTransientUnitTransportError::UnitAbsenceDeadlineElapsed);
        }
        let observed = timeout_at(deadline, async {
            wait_with_proxy(ManagerProxy::new(&self.connection).await, unit_name).await
        })
        .await
        .unwrap_or(Err(
            SystemdTransientUnitTransportError::UnitAbsenceDeadlineElapsed,
        ));
        if Instant::now() >= deadline {
            return Err(SystemdTransientUnitTransportError::UnitAbsenceDeadlineElapsed);
        }
        observed
    }
}

async fn wait_with_proxy(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
    unit_name: TransientServiceUnitName,
) -> AbsenceResult {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    loop {
        match proxy.get_unit(unit_name.as_str().to_owned()).await {
            Ok(_) => sleep(UNIT_POLL).await,
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == NO_SUCH_UNIT => {
                return Ok(SystemdAttemptUnitAbsenceObservation { unit_name });
            }
            Err(error) => return Err(SystemdTransientUnitTransportError::UnitLookup(error)),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
