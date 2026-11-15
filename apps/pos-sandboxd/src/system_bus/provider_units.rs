//! Manager operations on the selector-owned provider units (ADR-069 R11 §5.0,
//! R12 §7.2): listing a unit family, stopping one listed unit, and starting
//! one runtime unit.

use std::collections::BTreeSet;

use futures_util::StreamExt;
use tokio::time::Instant;
use zbus::OwnedVariant;
use zbus_systemd::systemd1::JobRemovedStream;

use super::{
    await_job_completion, classify_call_error, decode_job_completion, ManagerProxy,
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, TransientServiceUnitName,
    START_JOB_MODE, UNIT_SUFFIX,
};
use crate::provider_lifecycle::ProviderRuntimeUnitRequest;
use crate::provider_lifecycle::{
    CgroupRootSource, ProviderUnit, ProviderUnitFamily, StartedProviderUnit,
};
use crate::{AttemptShutdownDeadlines, SystemdAttemptUnitTeardownError};
use pos_reference::selector::runtime_lifecycle::ProviderLifecycleError;

type UnitsResult<T> = Result<T, SystemdTransientUnitTransportError>;

impl SystemdTransientUnitTransport {
    /// Every loaded unit of `family`, in any state, each resolved back to its
    /// listed object through `GetUnit`.
    ///
    /// # Errors
    /// Rejects listing and lookup failures, a noncanonical name, a duplicate
    /// name or object, and a name that resolves to another object.
    pub(crate) async fn observe_provider_units(
        &self,
        family: ProviderUnitFamily,
    ) -> UnitsResult<Vec<ProviderUnit>> {
        Self::observe_provider_units_with(ManagerProxy::new(&self.connection).await, family).await
    }

    /// [`Self::observe_provider_units`] over an already constructed proxy.
    pub(crate) async fn observe_provider_units_with(
        proxy: Result<ManagerProxy<'_>, zbus::Error>,
        family: ProviderUnitFamily,
    ) -> UnitsResult<Vec<ProviderUnit>> {
        let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
        let rows = proxy
            .list_units_by_patterns(Vec::new(), vec![format!("{}*", family.prefix())])
            .await
            .map_err(SystemdTransientUnitTransportError::InventoryCall)?;
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut units = Vec::with_capacity(rows.len());
        for row in rows {
            let name = parse_provider_name(family, &row.0)?;
            if !names.insert(row.0.clone()) || !paths.insert(row.6.as_str().to_owned()) {
                return Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch);
            }
            let resolved = proxy
                .get_unit(row.0)
                .await
                .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
            if resolved != row.6 {
                return Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch);
            }
            units.push(ProviderUnit::new(name, row.6));
        }
        Ok(units)
    }

    /// Stop one listed provider unit and prove it unloaded and its cgroup
    /// absent.
    ///
    /// The unit goes through the attempt units' bounded stop: stop and grace,
    /// the manager SIGKILL with `cgroup.kill`, `ResetFailedUnit`, and a fresh
    /// `GetUnit` absence (the owner's reading of ADR-087 §3 applies to a unit
    /// without a cgroup). The cgroup the manager reported before the stop must
    /// then be gone from the cgroup2 mount.
    ///
    /// # Errors
    /// [`ProviderLifecycleError::DeadlineExceeded`] when a phase misses its
    /// deadline, [`ProviderLifecycleError::Unavailable`] when the unit's
    /// cgroup cannot be read, and [`ProviderLifecycleError::ResidualResource`]
    /// for any other teardown failure or a remaining cgroup.
    pub(crate) async fn stop_provider_unit(
        &self,
        unit: &ProviderUnit,
        cgroup_root: &CgroupRootSource,
        shutdown: AttemptShutdownDeadlines,
        deadline: Instant,
    ) -> Result<(), ProviderLifecycleError> {
        let control_group = self
            .listed_control_group(unit.path())
            .await
            .map_err(|_| ProviderLifecycleError::Unavailable)?;
        self.stop_listed_with_root(
            unit.name(),
            unit.path(),
            cgroup_root(),
            (shutdown, deadline),
        )
        .await
        .map_err(|error| teardown_failure(&error))?;
        if control_group.is_empty() {
            return Ok(());
        }
        match cgroup_root().and_then(|root| root.contains(&control_group)) {
            Ok(false) => Ok(()),
            Ok(true) | Err(_) => Err(ProviderLifecycleError::ResidualResource),
        }
    }

    /// Start one runtime unit with exactly `request`'s properties, wait for its
    /// start job to end `done`, and read its `MainPID` and `ControlGroup` over
    /// the same connection.
    ///
    /// The job signal is subscribed before the start, so an immediately
    /// completed job cannot race the observer. Under `Type=notify`, `done`
    /// follows the daemon's `READY=1`.
    ///
    /// # Errors
    /// Rejects a refused start, a job that ends otherwise than `done`, a
    /// completion that names another unit, and a unit that is not the same
    /// object after its properties were read.
    pub(crate) async fn start_provider_runtime_unit(
        &self,
        name: &TransientServiceUnitName,
        request: &ProviderRuntimeUnitRequest,
    ) -> UnitsResult<StartedProviderUnit> {
        self.start_runtime_with(
            ManagerProxy::new(&self.connection).await,
            name,
            request.properties(),
        )
        .await
    }

    /// [`Self::start_provider_runtime_unit`] over an already constructed proxy
    /// and property bundle.
    pub(crate) async fn start_runtime_with(
        &self,
        proxy: Result<ManagerProxy<'_>, zbus::Error>,
        name: &TransientServiceUnitName,
        properties: Result<Vec<(String, OwnedVariant)>, zbus::Error>,
    ) -> UnitsResult<StartedProviderUnit> {
        let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
        let completions = proxy.receive_job_removed().await;
        self.start_runtime_with_completions(&proxy, completions, name, properties)
            .await
    }

    /// The start itself, once the job signal subscription was attempted.
    pub(crate) async fn start_runtime_with_completions(
        &self,
        proxy: &ManagerProxy<'_>,
        completions: Result<JobRemovedStream, zbus::Error>,
        name: &TransientServiceUnitName,
        properties: Result<Vec<(String, OwnedVariant)>, zbus::Error>,
    ) -> UnitsResult<StartedProviderUnit> {
        let mut completions = completions
            .map_err(SystemdTransientUnitTransportError::JobSignalSubscribe)?
            .map(|completion| decode_job_completion(completion.args()));
        let properties = properties.map_err(SystemdTransientUnitTransportError::Serialization)?;
        let job = proxy
            .start_transient_unit(
                name.as_str().to_owned(),
                START_JOB_MODE.to_owned(),
                properties,
                Vec::new(),
            )
            .await
            .map_err(classify_call_error)?;
        await_job_completion(&mut completions, job.as_str(), name.as_str().to_owned()).await?;
        let unit_path = self.unit_path_of(name).await?;
        let main_pid = self.read_main_pid(name).await?;
        let control_group = self.listed_control_group(&unit_path).await?;
        if self.unit_path_of(name).await? != unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        Ok(StartedProviderUnit::new(main_pid, control_group))
    }
}

const fn teardown_failure(error: &SystemdAttemptUnitTeardownError) -> ProviderLifecycleError {
    match error {
        SystemdAttemptUnitTeardownError::InvalidDeadlines
        | SystemdAttemptUnitTeardownError::DeadlineElapsed => {
            ProviderLifecycleError::DeadlineExceeded
        }
        _ => ProviderLifecycleError::ResidualResource,
    }
}

/// The canonical unit name of `family` that `listed` spells exactly.
fn parse_provider_name(
    family: ProviderUnitFamily,
    listed: &str,
) -> UnitsResult<TransientServiceUnitName> {
    let component = listed
        .strip_prefix(family.prefix())
        .and_then(|rest| rest.strip_suffix(UNIT_SUFFIX))
        .filter(|component| component.len() == 32 && component.is_ascii())
        .ok_or(SystemdTransientUnitTransportError::InventoryIdentityMismatch)?;
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&component[index * 2..index * 2 + 2], 16)
            .map_err(|_| SystemdTransientUnitTransportError::InventoryIdentityMismatch)?;
    }
    TransientServiceUnitName::provider_unit(family, id)
        .ok()
        .filter(|canonical| canonical.as_str() == listed)
        .ok_or(SystemdTransientUnitTransportError::InventoryIdentityMismatch)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_family_names_are_parsed() -> Result<(), Box<dyn std::error::Error>> {
        let runtime =
            TransientServiceUnitName::provider_unit(ProviderUnitFamily::Runtime, [0xab; 16])?;
        assert_eq!(
            runtime.as_str(),
            format!("pigloros-provider-runtime-{}.service", "ab".repeat(16))
        );
        assert_eq!(runtime.attempt_component(), "ab".repeat(16));
        assert_eq!(
            parse_provider_name(ProviderUnitFamily::Runtime, runtime.as_str())?,
            runtime
        );
        let recovery =
            TransientServiceUnitName::provider_unit(ProviderUnitFamily::Recovery, [0x01; 16])?;
        assert_eq!(
            recovery.as_str(),
            format!("pigloros-provider-recovery-{}.service", "01".repeat(16))
        );
        assert_eq!(
            parse_provider_name(ProviderUnitFamily::Recovery, recovery.as_str())?,
            recovery
        );
        for (family, listed) in [
            (ProviderUnitFamily::Recovery, runtime.as_str().to_owned()),
            (ProviderUnitFamily::Runtime, recovery.as_str().to_owned()),
            (
                ProviderUnitFamily::Runtime,
                format!("pigloros-provider-runtime-{}.service", "AB".repeat(16)),
            ),
            (
                ProviderUnitFamily::Runtime,
                format!("pigloros-provider-runtime-{}.service", "00".repeat(16)),
            ),
            (
                ProviderUnitFamily::Runtime,
                format!("pigloros-provider-runtime-{}.service", "gh".repeat(16)),
            ),
            (
                ProviderUnitFamily::Runtime,
                format!("pigloros-provider-runtime-{}.service", "é".repeat(16)),
            ),
            (
                ProviderUnitFamily::Runtime,
                format!("pigloros-provider-runtime-{}.scope", "ab".repeat(16)),
            ),
            (
                ProviderUnitFamily::Runtime,
                "pigloros-provider-runtime-ab.service".to_owned(),
            ),
        ] {
            assert!(
                matches!(
                    parse_provider_name(family, &listed),
                    Err(SystemdTransientUnitTransportError::InventoryIdentityMismatch)
                ),
                "{listed}"
            );
        }
        Ok(())
    }

    #[test]
    fn missed_deadlines_and_other_teardown_failures_are_distinguished() {
        assert_eq!(
            teardown_failure(&SystemdAttemptUnitTeardownError::InvalidDeadlines),
            ProviderLifecycleError::DeadlineExceeded
        );
        assert_eq!(
            teardown_failure(&SystemdAttemptUnitTeardownError::DeadlineElapsed),
            ProviderLifecycleError::DeadlineExceeded
        );
        assert_eq!(
            teardown_failure(&SystemdAttemptUnitTeardownError::Transport(
                SystemdTransientUnitTransportError::CgrouplessUnitActive
            )),
            ProviderLifecycleError::ResidualResource
        );
    }
}
