//! The attempt unit's pin and the evidence read around its release and exit
//! (ADR-069 R9 §4.6.6, §4.6.7 and the watchdog anchor of §4.6.5).
//!
//! With systemd's default garbage collection a successful transient service
//! is unloaded once unreferenced, taking its `Result`, `ExecMainCode` and
//! `ExecMainStatus` with it. The provider therefore references the unit with
//! `RefUnit` before its cgroup is bound, reads the result after exit, and
//! releases it with `UnrefUnit` before teardown. All three calls, and the
//! activation-time read, go over the transport's single retained
//! connection: systemd tracks the reference by that client's bus name, so a
//! lost connection drops the pin and the result is then missing evidence,
//! never read again elsewhere.

use std::fs::File;
use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;
use zbus::proxy::CacheProperties;
use zbus_systemd::systemd1::{ManagerProxy, UnitProxy};

use super::{
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, SystemdUnitResultError,
    SystemdUnitResultObservation, SystemdVerifiedStart, TransientServiceUnitName,
};
use crate::{
    BoundAttemptCgroup, ReleaseResources, TerminalResources, TerminalServiceError, WorkUsage,
};

const NANOSECONDS_PER_MICROSECOND: u64 = 1_000;
/// How often an unsettled unit's result is read again.
const SETTLE_POLL: Duration = Duration::from_millis(10);

type TransportResult<T> = Result<T, SystemdTransientUnitTransportError>;

impl SystemdTransientUnitTransport {
    /// Reference the unit, then run `bind`. A failed `bind` releases the
    /// reference again, best effort: nothing will read the unit's result. So
    /// does a reference or a `bind` that is cut off or dropped: `RefUnit`
    /// may have been sent with its reply never awaited, and releasing a unit
    /// that was not referenced is harmless. Every release runs once, on a
    /// task over the same connection, so cutting off the wait for it neither
    /// leaks the pin nor repeats the release.
    pub(crate) async fn pinned<T>(
        &self,
        unit: &TransientServiceUnitName,
        bind: impl Future<Output = TransportResult<T>>,
    ) -> TransportResult<T> {
        let mut guard = PinGuard(Some((self.connection.clone(), unit.clone())));
        if let Err(refused) = pin_with(ManagerProxy::new(&self.connection).await, unit).await {
            guard.disarm();
            return Err(refused);
        }
        let bound = bind.await;
        let release = if bound.is_err() {
            guard.release()
        } else {
            None
        };
        if let Some(release) = release {
            release.await.ok();
        }
        guard.disarm();
        bound
    }

    /// Release the unit's reference.
    pub(crate) async fn unpin(&self, unit: &TransientServiceUnitName) -> TransportResult<()> {
        unpin_with(ManagerProxy::new(&self.connection).await, unit).await
    }

    /// The unit's activation time, then the bound cgroup's baseline counters
    /// and effective kernel limits.
    pub(crate) async fn release_resources(
        &self,
        started: &SystemdVerifiedStart,
        cgroup: &BoundAttemptCgroup,
    ) -> TransportResult<(u64, ReleaseResources)> {
        let unit = UnitProxy::builder(&self.connection)
            .path(started.unit_path.clone())
            .cache_properties(CacheProperties::No)
            .build()
            .await;
        let activated = activated_with(unit).await?;
        let baseline = cgroup.capture_limit_events()?;
        let effective = cgroup.read_effective_limits()?;
        Ok((
            activated,
            ReleaseResources::new(activated, baseline, effective),
        ))
    }

    /// The terminal evidence of the exited `unit`, before teardown: its
    /// cgroup counters, its `/work` usage, its settled result and the release
    /// of its pin, in that order.
    ///
    /// `started` is the verified start and the `InvocationID` the frozen
    /// kernel observation recorded, which the result must belong to. It is
    /// `None` when either is unknown; the result is then missing. An
    /// unsettled result is read again until `settle_by`.
    pub(crate) async fn conclude(
        &self,
        unit: &TransientServiceUnitName,
        started: Option<(&SystemdVerifiedStart, [u8; 16])>,
        cgroup: &BoundAttemptCgroup,
        work: Option<&File>,
        settle_by: Instant,
    ) -> TerminalResources {
        let terminal = cgroup.capture_limit_events();
        let work_after = work.map(WorkUsage::observe);
        let service = self.settled_result(started, settle_by).await;
        let unpinned = self.unpin(unit).await;
        TerminalResources::new(terminal, work_after, service, unpinned)
    }

    /// The unit's result once it settled, or the last failure at `settle_by`.
    async fn settled_result(
        &self,
        started: Option<(&SystemdVerifiedStart, [u8; 16])>,
        settle_by: Instant,
    ) -> Result<SystemdUnitResultObservation, TerminalServiceError> {
        let Some((started, invocation)) = started else {
            return Err(TerminalServiceError::Unstarted);
        };
        let mut read = self.read_unit_result(started, invocation).await;
        while matches!(read, Err(SystemdUnitResultError::NotSettled { .. }))
            && !settle_by
                .saturating_duration_since(Instant::now())
                .is_zero()
        {
            tokio::time::sleep(SETTLE_POLL).await;
            read = self.read_unit_result(started, invocation).await;
        }
        read.map_err(TerminalServiceError::from)
    }
}

/// A reference whose request or `bind` has not finished; dropped armed, it
/// is released by a task on the connection that took it.
struct PinGuard(Option<(zbus::Connection, TransientServiceUnitName)>);

impl PinGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }

    /// Release the reference now, once, from a task that outlives whoever
    /// awaits it.
    fn release(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        match (self.0.take(), tokio::runtime::Handle::try_current()) {
            (Some((connection, unit)), Ok(runtime)) => Some(runtime.spawn(async move {
                unpin_with(ManagerProxy::new(&connection).await, &unit)
                    .await
                    .ok();
            })),
            _ => None,
        }
    }
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        drop(self.release());
    }
}

async fn pin_with(
    proxy: zbus::Result<ManagerProxy<'_>>,
    unit: &TransientServiceUnitName,
) -> TransportResult<()> {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    // Bound to a local so the call's temporaries drop before `proxy` (the
    // tail-expression drop order that Rust 2024 changes).
    let referenced = proxy
        .ref_unit(unit.as_str().to_owned())
        .await
        .map_err(SystemdTransientUnitTransportError::UnitRef);
    referenced
}

async fn unpin_with(
    proxy: zbus::Result<ManagerProxy<'_>>,
    unit: &TransientServiceUnitName,
) -> TransportResult<()> {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    // Bound to a local for the same drop order as `pin_with`.
    let released = proxy
        .unref_unit(unit.as_str().to_owned())
        .await
        .map_err(SystemdTransientUnitTransportError::UnitUnref);
    released
}

/// `ActiveEnterTimestampMonotonic` in nanoseconds; zero is no activation.
async fn activated_with(unit: zbus::Result<UnitProxy<'_>>) -> TransportResult<u64> {
    let unit = unit.map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
    let microseconds = unit
        .active_enter_timestamp_monotonic()
        .await
        .map_err(
            |source| SystemdTransientUnitTransportError::PropertyReadback {
                property: "ActiveEnterTimestampMonotonic",
                source: Box::new(source),
            },
        )?;
    microseconds
        .checked_mul(NANOSECONDS_PER_MICROSECOND)
        .filter(|&nanoseconds| nanoseconds != 0)
        .ok_or(SystemdTransientUnitTransportError::ActivationUnset)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
