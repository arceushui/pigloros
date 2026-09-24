//! Typed system-bus submission and requested-state verification.

use std::future::Future;

use futures_util::{Stream, StreamExt};
use zbus::{proxy::CacheProperties, zvariant::OwnedObjectPath, Connection};
use zbus_systemd::systemd1::{JobRemovedArgs, JobRemovedStream, ManagerProxy, ServiceProxy};
use zvariant::{Fd, OwnedFd, OwnedValue, Value};

use crate::{
    AttemptCgroupError, BoundAttemptCgroup, CgroupRoot, SystemdHardeningProperty,
    SystemdHardeningReadbackValue, SystemdHardeningValue, SystemdManagerReadback,
    SystemdManagerReadbackOnlyProperty, SystemdTransientUnitProperty,
    SystemdTransientUnitPropertyAccess, SystemdTransientUnitPropertyKind,
    SystemdTransientUnitReadback, SystemdTransientUnitReadbackValue, SystemdTransientUnitValue,
    TransientUnitRequest, TransientUnitRequestError,
};
use crate::{SystemdDynamicPropertyKind, SystemdOperatingLimitProperty};

const START_JOB_MODE: &str = "fail";
// A stop must displace a conflicting queued start job for the same attempt unit.
const STOP_JOB_MODE: &str = "replace";
const KILL_WHOM: &str = "all";
const SIGKILL: i32 = 9;
const UNIT_PREFIX: &str = "pigloros-attempt-";
const UNIT_SUFFIX: &str = ".service";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// The deterministic transient service-unit name for one sandbox attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientServiceUnitName(String);

impl TransientServiceUnitName {
    /// Derive the collision-resistant unit name from the authoritative attempt ID.
    ///
    /// # Errors
    /// Returns [`TransientServiceUnitNameError::ZeroAttemptId`] when the
    /// identifier is not a valid nonzero attempt identity.
    pub fn from_attempt_id(attempt_id: [u8; 16]) -> Result<Self, TransientServiceUnitNameError> {
        if attempt_id == [0; 16] {
            return Err(TransientServiceUnitNameError::ZeroAttemptId);
        }
        let mut name = String::with_capacity(UNIT_PREFIX.len() + 32 + UNIT_SUFFIX.len());
        name.push_str(UNIT_PREFIX);
        for byte in attempt_id {
            name.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
            name.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
        }
        name.push_str(UNIT_SUFFIX);
        Ok(Self(name))
    }

    /// Return the exact systemd unit name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Failure to construct a valid transient service-unit name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransientServiceUnitNameError {
    /// ADR-069 reserves the all-zero value and requires a nonzero attempt ID.
    #[error("the transient service-unit attempt ID must be nonzero")]
    ZeroAttemptId,
}

/// The typed systemd job identity returned after request submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdStartJob(OwnedObjectPath);

impl SystemdStartJob {
    /// Return the exact systemd job object path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A systemd unit-job result that cannot authorize the next lifecycle step.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SystemdJobFailure {
    /// The job was explicitly cancelled.
    #[error("systemd cancelled the transient-unit job")]
    Canceled,
    /// The job exceeded its systemd job timeout.
    #[error("the systemd transient-unit job timed out")]
    Timeout,
    /// The job failed.
    #[error("the systemd transient-unit job failed")]
    Failed,
    /// A dependency job failed.
    #[error("a dependency of the systemd transient-unit job failed")]
    Dependency,
    /// systemd skipped the job.
    #[error("systemd skipped the transient-unit job")]
    Skipped,
    /// A newer or malformed manager returned an unrecognized result.
    #[error("systemd returned unknown transient-unit job result {0:?}")]
    Unknown(String),
}

impl SystemdJobFailure {
    fn from_result(result: String) -> Option<Self> {
        match result.as_str() {
            "done" => None,
            "canceled" => Some(Self::Canceled),
            "timeout" => Some(Self::Timeout),
            "failed" => Some(Self::Failed),
            "dependency" => Some(Self::Dependency),
            "skipped" => Some(Self::Skipped),
            _ => Some(Self::Unknown(result)),
        }
    }
}

struct SystemdJobCompletion {
    job: OwnedObjectPath,
    unit: String,
    result: String,
}

fn decode_job_completion(
    args: Result<JobRemovedArgs<'_>, zbus::Error>,
) -> Result<SystemdJobCompletion, SystemdTransientUnitTransportError> {
    let args = args.map_err(SystemdTransientUnitTransportError::JobSignal)?;
    Ok(SystemdJobCompletion {
        job: args.job().clone(),
        unit: args.unit().clone(),
        result: args.result().clone(),
    })
}

async fn await_job_completion<S>(
    completions: &mut S,
    job_path: &str,
    submitted_name: String,
) -> Result<(), SystemdTransientUnitTransportError>
where
    S: Stream<Item = Result<SystemdJobCompletion, SystemdTransientUnitTransportError>> + Unpin,
{
    loop {
        let completion = completions
            .next()
            .await
            .ok_or(SystemdTransientUnitTransportError::JobSignalEnded)??;
        if completion.job.as_str() != job_path {
            continue;
        }
        if completion.unit != submitted_name {
            return Err(SystemdTransientUnitTransportError::JobIdentityMismatch {
                expected: submitted_name,
                actual: completion.unit,
            });
        }
        if let Some(failure) = SystemdJobFailure::from_result(completion.result) {
            return Err(failure.into());
        }
        return Ok(());
    }
}

/// One exact `StopUnit` job that completed successfully.
///
/// This is a command observation, not unit absence, cgroup emptiness, or full
/// attempt-cleanup evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdStopJobCompleted {
    unit_name: TransientServiceUnitName,
    job: OwnedObjectPath,
}

impl SystemdStopJobCompleted {
    /// Return the deterministic unit that received the stop command.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Return the exact completed stop-job object path.
    #[must_use]
    pub fn job_path(&self) -> &str {
        self.job.as_str()
    }
}

/// One successful systemd start whose complete requested state was read back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdVerifiedStart {
    unit_name: TransientServiceUnitName,
    job: SystemdStartJob,
    unit_path: OwnedObjectPath,
    requested_readback: Vec<SystemdTransientUnitReadback>,
    manager_readback: SystemdManagerReadback,
}

impl SystemdVerifiedStart {
    /// Return the exact transient service-unit name.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Return the completed systemd start-job identity.
    #[must_use]
    pub const fn job(&self) -> &SystemdStartJob {
        &self.job
    }

    /// Return the exact systemd unit object path used for typed readback.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        self.unit_path.as_str()
    }

    /// Return the complete verified requested-state readback in canonical order.
    #[must_use]
    pub fn requested_readback(&self) -> &[SystemdTransientUnitReadback] {
        &self.requested_readback
    }

    /// Return the separately recorded manager-only effective state.
    #[must_use]
    pub const fn manager_readback(&self) -> &SystemdManagerReadback {
        &self.manager_readback
    }
}

/// Fail-closed failures at the typed transient-unit command boundary.
#[derive(Debug, thiserror::Error)]
pub enum SystemdTransientUnitTransportError {
    /// The process could not establish its privileged system-bus connection.
    #[error("failed to connect to the system D-Bus")]
    Connect(#[source] zbus::Error),
    /// The generated systemd manager proxy could not be constructed.
    #[error("failed to construct the typed systemd manager proxy")]
    Proxy(#[source] zbus::Error),
    /// The systemd manager rejected signal subscription for this connection.
    #[error("failed to subscribe the systemd manager connection")]
    ManagerSubscribe(#[source] zbus::Error),
    /// One closed request value could not be serialized for D-Bus.
    #[error("failed to serialize the typed transient-unit request")]
    Serialization(#[source] zvariant::Error),
    /// systemd rejected or failed the typed `StartTransientUnit` call.
    #[error("systemd rejected the transient-unit request")]
    ManagerCall(#[source] zbus::Error),
    /// systemd rejected or failed the typed `StopUnit` call.
    #[error("systemd rejected the transient-unit stop request")]
    StopCall(#[source] zbus::Error),
    /// systemd rejected or failed the typed whole-unit `KillUnit` call.
    #[error("systemd rejected the transient-unit force-kill request")]
    KillCall(#[source] zbus::Error),
    /// The manager's job-completion signal could not be subscribed to.
    #[error("failed to subscribe to systemd transient-unit job completion")]
    JobSignalSubscribe(#[source] zbus::Error),
    /// One job-completion signal had an invalid typed body.
    #[error("failed to decode systemd transient-unit job completion")]
    JobSignal(#[source] zbus::Error),
    /// The job-completion stream ended before the submitted job completed.
    #[error("systemd job-completion stream ended before the transient-unit job completed")]
    JobSignalEnded,
    /// The returned job path was reused for a different unit identity.
    #[error("systemd job completion named {actual:?}, expected {expected:?}")]
    JobIdentityMismatch { expected: String, actual: String },
    /// The matching job did not complete successfully.
    #[error(transparent)]
    JobFailed(#[from] SystemdJobFailure),
    /// The completed transient unit could not be resolved to an object path.
    #[error("failed to resolve the completed systemd transient unit")]
    UnitLookup(#[source] zbus::Error),
    /// The generated typed service proxy could not be constructed.
    #[error("failed to construct the typed systemd service proxy")]
    ServiceProxy(#[source] zbus::Error),
    /// The exact attempt unit could not be identified at cgroup binding time.
    #[error("systemd attempt-unit identity changed before cgroup binding")]
    CgroupUnitMismatch,
    /// The typed service `ControlGroup` property could not be read.
    #[error("failed to read the exact systemd attempt ControlGroup")]
    CgroupReadback(#[source] zbus::Error),
    /// The manager could not reverse-map `ControlGroup` to its unit object.
    #[error("failed to reverse-map the systemd attempt ControlGroup")]
    CgroupReverseLookup(#[source] zbus::Error),
    /// The manager-bound cgroup could not be safely opened or observed.
    #[error(transparent)]
    CgroupKernel(#[from] AttemptCgroupError),
    /// One typed systemd service property could not be read.
    #[error("failed to read systemd transient-unit property {property}")]
    PropertyReadback {
        property: &'static str,
        #[source]
        source: Box<zbus::Error>,
    },
    /// The complete typed property readback differed from the compiled request.
    #[error("systemd transient-unit requested-state verification failed")]
    Readback(#[source] TransientUnitRequestError),
}

/// A generated, typed systemd Manager transport over one D-Bus connection.
pub struct SystemdTransientUnitTransport {
    connection: Connection,
}

impl SystemdTransientUnitTransport {
    /// Connect to the host system bus used by the privileged provider.
    ///
    /// # Errors
    /// Returns [`SystemdTransientUnitTransportError::Connect`] when the system bus is
    /// unavailable or rejects the connection.
    pub async fn connect_system() -> Result<Self, SystemdTransientUnitTransportError> {
        Self::connect_with(Connection::system()).await
    }

    async fn connect_with<F>(connection: F) -> Result<Self, SystemdTransientUnitTransportError>
    where
        F: Future<Output = Result<Connection, zbus::Error>>,
    {
        let connection = connection
            .await
            .map_err(SystemdTransientUnitTransportError::Connect)?;
        Self::from_connection(connection).await
    }

    async fn from_connection(
        connection: Connection,
    ) -> Result<Self, SystemdTransientUnitTransportError> {
        let subscription = Self::subscribe_manager(ManagerProxy::new(&connection).await).await;
        subscription.map(|()| Self { connection })
    }

    async fn subscribe_manager(
        proxy: Result<ManagerProxy<'_>, zbus::Error>,
    ) -> Result<(), SystemdTransientUnitTransportError> {
        let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
        proxy
            .subscribe()
            .await
            .map_err(SystemdTransientUnitTransportError::ManagerSubscribe)?;
        Ok(())
    }

    /// Submit, await, and verify one complete compiled request.
    ///
    /// The manager signal subscription is established before submission so an
    /// immediately completed job cannot race the observer. Success proves exact
    /// requested-state readback only; it does not establish launcher readiness,
    /// release, image admission, or kernel enforcement.
    ///
    /// # Errors
    /// Returns a classified connection, submission, job-completion, typed
    /// property-readback, or requested-state verification failure.
    pub async fn start(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
    ) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
        let properties = request.requested_properties_for_submission();
        self.start_with_prepared(unit_name, request, properties)
            .await
    }

    /// Submit and await the exact stop job for one deterministic attempt unit.
    ///
    /// A queued start job may be replaced; its cancellation cannot satisfy
    /// the returned stop-job path.
    ///
    /// The caller must bound the wait and later prove unit/cgroup absence. A
    /// completed stop job is not a terminal attempt-cleanup proof.
    ///
    /// # Errors
    /// Rejects a proxy, subscription, call, signal, identity, or job-result
    /// failure without claiming the unit was stopped.
    pub async fn stop_job(
        &self,
        unit_name: TransientServiceUnitName,
    ) -> Result<SystemdStopJobCompleted, SystemdTransientUnitTransportError> {
        stop_job_with_proxy(ManagerProxy::new(&self.connection).await, unit_name).await
    }

    /// Send SIGKILL to all processes of one deterministic attempt unit.
    ///
    /// This explicit escalation is only a command acknowledgement. The caller
    /// must separately read back cgroup emptiness and complete resource cleanup.
    ///
    /// # Errors
    /// Rejects a proxy or manager-call failure without claiming termination.
    pub async fn force_kill(
        &self,
        unit_name: TransientServiceUnitName,
    ) -> Result<(), SystemdTransientUnitTransportError> {
        force_kill_with_proxy(ManagerProxy::new(&self.connection).await, unit_name).await
    }

    /// Bind the exact verified attempt unit to its kernel cgroup before termination.
    ///
    /// This read-only operation verifies the manager-to-cgroup mapping in both
    /// directions and retains the kernel handle. It does not prove enforcement,
    /// process emptiness, or complete attempt cleanup.
    ///
    /// # Errors
    /// Rejects unavailable, substituted, changed, malformed, or unsafe unit and
    /// kernel cgroup identities.
    pub async fn bind_cgroup(
        &self,
        verified: &SystemdVerifiedStart,
    ) -> Result<BoundAttemptCgroup, SystemdTransientUnitTransportError> {
        self.bind_cgroup_with_root_result(verified, CgroupRoot::system())
            .await
    }

    async fn bind_cgroup_with_root_result(
        &self,
        verified: &SystemdVerifiedStart,
        root: Result<CgroupRoot, AttemptCgroupError>,
    ) -> Result<BoundAttemptCgroup, SystemdTransientUnitTransportError> {
        let root = root?;
        self.bind_cgroup_with_root(verified, root).await
    }

    async fn bind_cgroup_with_root(
        &self,
        verified: &SystemdVerifiedStart,
        root: CgroupRoot,
    ) -> Result<BoundAttemptCgroup, SystemdTransientUnitTransportError> {
        let manager = ManagerProxy::new(&self.connection)
            .await
            .map_err(SystemdTransientUnitTransportError::Proxy)?;
        let current_unit = manager
            .get_unit(verified.unit_name.as_str().to_owned())
            .await
            .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
        if current_unit != verified.unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        let service = ServiceProxy::builder(&self.connection)
            .path(verified.unit_path.clone())
            .map_err(SystemdTransientUnitTransportError::ServiceProxy)?
            // The second ControlGroup read must reach systemd, not a proxy cache.
            .cache_properties(CacheProperties::No)
            .build()
            .await
            .map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
        let path = service
            .control_group()
            .await
            .map_err(SystemdTransientUnitTransportError::CgroupReadback)?;
        let reverse = manager
            .get_unit_by_control_group(path.clone())
            .await
            .map_err(SystemdTransientUnitTransportError::CgroupReverseLookup)?;
        if reverse != verified.unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        let bound = BoundAttemptCgroup::open(
            root,
            verified.unit_name.clone(),
            verified.unit_path.clone(),
            path.clone(),
        )?;
        let reread = service
            .control_group()
            .await
            .map_err(SystemdTransientUnitTransportError::CgroupReadback)?;
        if reread != path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        let reverse_again = manager
            .get_unit_by_control_group(reread)
            .await
            .map_err(SystemdTransientUnitTransportError::CgroupReverseLookup)?;
        if reverse_again != verified.unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        let current_unit_again = manager
            .get_unit(verified.unit_name.as_str().to_owned())
            .await
            .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
        if current_unit_again != verified.unit_path {
            return Err(SystemdTransientUnitTransportError::CgroupUnitMismatch);
        }
        Ok(bound)
    }

    async fn start_with_prepared(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
        properties: Result<Vec<SystemdTransientUnitProperty>, zvariant::Error>,
    ) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
        let properties = properties
            .map_err(SystemdTransientUnitTransportError::Serialization)?
            .into_iter()
            .map(encode_property)
            .collect::<Result<Vec<_>, _>>();
        self.start_with_encoded(unit_name, request, properties)
            .await
    }

    async fn start_with_encoded(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
        properties: Result<Vec<(String, OwnedValue)>, SystemdTransientUnitTransportError>,
    ) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
        let properties = properties?;
        let proxy = ManagerProxy::new(&self.connection).await;
        submit_and_verify(proxy, properties, unit_name, &request, &self.connection).await
    }
}

async fn stop_job_with_proxy(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
    unit_name: TransientServiceUnitName,
) -> Result<SystemdStopJobCompleted, SystemdTransientUnitTransportError> {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    let completions = proxy.receive_job_removed().await;
    let result = stop_job_with_completions(&proxy, completions, unit_name).await;
    result
}

async fn stop_job_with_completions(
    proxy: &ManagerProxy<'_>,
    completions: Result<JobRemovedStream, zbus::Error>,
    unit_name: TransientServiceUnitName,
) -> Result<SystemdStopJobCompleted, SystemdTransientUnitTransportError> {
    let completions =
        completions.map_err(SystemdTransientUnitTransportError::JobSignalSubscribe)?;
    let mut completions = completions.map(|completion| decode_job_completion(completion.args()));
    let result = stop_job_with_stream(proxy, &mut completions, unit_name).await;
    result
}

async fn stop_job_with_stream<S>(
    proxy: &ManagerProxy<'_>,
    completions: &mut S,
    unit_name: TransientServiceUnitName,
) -> Result<SystemdStopJobCompleted, SystemdTransientUnitTransportError>
where
    S: Stream<Item = Result<SystemdJobCompletion, SystemdTransientUnitTransportError>> + Unpin,
{
    let name = unit_name.as_str().to_owned();
    let job = proxy
        .stop_unit(name.clone(), STOP_JOB_MODE.to_owned())
        .await
        .map_err(SystemdTransientUnitTransportError::StopCall)?;
    await_job_completion(completions, job.as_str(), name).await?;
    Ok(SystemdStopJobCompleted { unit_name, job })
}

async fn force_kill_with_proxy(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
    unit_name: TransientServiceUnitName,
) -> Result<(), SystemdTransientUnitTransportError> {
    let proxy = proxy.map_err(SystemdTransientUnitTransportError::Proxy)?;
    let result = proxy
        .kill_unit(unit_name.as_str().to_owned(), KILL_WHOM.to_owned(), SIGKILL)
        .await
        .map_err(SystemdTransientUnitTransportError::KillCall);
    result
}

async fn submit_and_verify(
    proxy: Result<ManagerProxy<'_>, zbus::Error>,
    properties: Vec<(String, OwnedValue)>,
    unit_name: TransientServiceUnitName,
    request: &TransientUnitRequest,
    connection: &Connection,
) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
    let proxy = match proxy {
        Ok(proxy) => proxy,
        Err(error) => return Err(SystemdTransientUnitTransportError::Proxy(error)),
    };
    let completions = proxy.receive_job_removed().await;
    let result = submit_with_completions(
        &proxy,
        completions,
        properties,
        unit_name,
        request,
        connection,
    )
    .await;
    result
}

async fn submit_with_completions(
    proxy: &ManagerProxy<'_>,
    completions: Result<JobRemovedStream, zbus::Error>,
    properties: Vec<(String, OwnedValue)>,
    unit_name: TransientServiceUnitName,
    request: &TransientUnitRequest,
    connection: &Connection,
) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
    let completions =
        completions.map_err(SystemdTransientUnitTransportError::JobSignalSubscribe)?;
    let mut completions = completions.map(|completion| decode_job_completion(completion.args()));
    let submitted_name = unit_name.0.clone();
    let job_path = match proxy
        .start_transient_unit(
            submitted_name.clone(),
            START_JOB_MODE.to_owned(),
            properties,
            Vec::new(),
        )
        .await
    {
        Ok(job_path) => job_path,
        Err(error) => return Err(classify_call_error(error)),
    };
    let job = SystemdStartJob(job_path);
    await_job_completion(&mut completions, job.as_str(), submitted_name.clone()).await?;
    let unit_path = proxy
        .get_unit(submitted_name)
        .await
        .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
    let service = ServiceProxy::builder(connection)
        .path(unit_path.clone())
        .map_err(SystemdTransientUnitTransportError::ServiceProxy)?
        .build()
        .await;
    let result = verify_service(service, unit_name, job, unit_path, request).await;
    result
}

async fn verify_service(
    service: Result<ServiceProxy<'_>, zbus::Error>,
    unit_name: TransientServiceUnitName,
    job: SystemdStartJob,
    unit_path: OwnedObjectPath,
    request: &TransientUnitRequest,
) -> Result<SystemdVerifiedStart, SystemdTransientUnitTransportError> {
    let service = service.map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
    let requested_readback = read_requested_properties(&service, request).await?;
    request
        .verify_readback(&requested_readback)
        .map_err(SystemdTransientUnitTransportError::Readback)?;
    let root_image_policy = service.root_image_policy().await.map_err(|source| {
        SystemdTransientUnitTransportError::PropertyReadback {
            property: SystemdManagerReadbackOnlyProperty::RootImagePolicy.name(),
            source: Box::new(source),
        }
    })?;
    Ok(SystemdVerifiedStart {
        unit_name,
        job,
        unit_path,
        requested_readback,
        manager_readback: SystemdManagerReadback::new(
            SystemdManagerReadbackOnlyProperty::RootImagePolicy,
            root_image_policy,
        ),
    })
}

async fn read_requested_properties(
    service: &ServiceProxy<'_>,
    request: &TransientUnitRequest,
) -> Result<Vec<SystemdTransientUnitReadback>, SystemdTransientUnitTransportError> {
    let mut readback = Vec::with_capacity(request.requested_properties().len());
    for property in request.requested_properties() {
        let kind = property.kind();
        let value = read_property(service, kind).await.map_err(|source| {
            SystemdTransientUnitTransportError::PropertyReadback {
                property: kind.name(),
                source: Box::new(source),
            }
        })?;
        readback.push(SystemdTransientUnitReadback::new(property.name(), value));
    }
    Ok(readback)
}

async fn read_property(
    service: &ServiceProxy<'_>,
    kind: SystemdTransientUnitPropertyKind,
) -> Result<SystemdTransientUnitReadbackValue, zbus::Error> {
    match kind {
        SystemdTransientUnitPropertyKind::Hardening(property) => read_hardening(service, property)
            .await
            .map(SystemdTransientUnitReadbackValue::Static),
        SystemdTransientUnitPropertyKind::Dynamic(property) => {
            read_dynamic_property(service, property).await
        }
    }
}

async fn read_dynamic_property(
    service: &ServiceProxy<'_>,
    kind: SystemdDynamicPropertyKind,
) -> Result<SystemdTransientUnitReadbackValue, zbus::Error> {
    match kind {
        SystemdDynamicPropertyKind::RootDirectory => service
            .root_directory()
            .await
            .map(SystemdTransientUnitReadbackValue::String),
        SystemdDynamicPropertyKind::BindReadOnlyPaths => service
            .bind_read_only_paths()
            .await
            .map(SystemdTransientUnitReadbackValue::BindReadOnlyPaths),
        SystemdDynamicPropertyKind::SystemCallFilter => service
            .system_call_filter()
            .await
            .map(SystemdTransientUnitReadbackValue::BoolStringArray),
        SystemdDynamicPropertyKind::RestrictAddressFamilies => service
            .restrict_address_families()
            .await
            .map(SystemdTransientUnitReadbackValue::BoolStringArray),
        SystemdDynamicPropertyKind::OperatingLimit(property) => {
            read_operating_limit(service, property)
                .await
                .map(SystemdTransientUnitReadbackValue::U64)
        }
        SystemdDynamicPropertyKind::FileDescriptorStoreMax => service
            .file_descriptor_store_max()
            .await
            .map(SystemdTransientUnitReadbackValue::U32),
        SystemdDynamicPropertyKind::ExtraFileDescriptors => service
            .extra_file_descriptor_names()
            .await
            .map(SystemdTransientUnitReadbackValue::StringArray),
    }
}

async fn read_operating_limit(
    service: &ServiceProxy<'_>,
    property: SystemdOperatingLimitProperty,
) -> Result<u64, zbus::Error> {
    match property {
        SystemdOperatingLimitProperty::MemoryMax => service.memory_max().await,
        SystemdOperatingLimitProperty::MemorySwapMax => service.memory_swap_max().await,
        SystemdOperatingLimitProperty::TasksMax => service.tasks_max().await,
        SystemdOperatingLimitProperty::CpuQuotaPerSecUSec => {
            service.cpu_quota_per_sec_u_sec().await
        }
        SystemdOperatingLimitProperty::RuntimeMaxUSec => service.runtime_max_u_sec().await,
        SystemdOperatingLimitProperty::LimitNofile => service.limit_nofile().await,
        SystemdOperatingLimitProperty::LimitFsize => service.limit_fsize().await,
    }
}

async fn read_hardening(
    service: &ServiceProxy<'_>,
    property: SystemdHardeningProperty,
) -> Result<SystemdHardeningReadbackValue, zbus::Error> {
    match property {
        SystemdHardeningProperty::TypeExec => service.type_property().await.map(string_readback),
        SystemdHardeningProperty::DynamicUser => service.dynamic_user().await.map(bool_readback),
        SystemdHardeningProperty::NoNewPrivileges => {
            service.no_new_privileges().await.map(bool_readback)
        }
        SystemdHardeningProperty::PrivateDevices => {
            service.private_devices().await.map(bool_readback)
        }
        SystemdHardeningProperty::PrivateIpc => service.private_ipc().await.map(bool_readback),
        SystemdHardeningProperty::PrivateMounts => {
            service.private_mounts().await.map(bool_readback)
        }
        SystemdHardeningProperty::PrivateNetwork => {
            service.private_network().await.map(bool_readback)
        }
        SystemdHardeningProperty::PrivatePids => service.private_pi_ds().await.map(string_readback),
        SystemdHardeningProperty::PrivateUsersEx => {
            service.private_users_ex().await.map(string_readback)
        }
        SystemdHardeningProperty::CapabilityBoundingSet => {
            service.capability_bounding_set().await.map(u64_readback)
        }
        SystemdHardeningProperty::AmbientCapabilities => {
            service.ambient_capabilities().await.map(u64_readback)
        }
        SystemdHardeningProperty::ProtectSystem => {
            service.protect_system().await.map(string_readback)
        }
        SystemdHardeningProperty::ProtectHome => service.protect_home().await.map(string_readback),
        SystemdHardeningProperty::ProtectControlGroupsEx => service
            .protect_control_groups_ex()
            .await
            .map(string_readback),
        SystemdHardeningProperty::ProtectKernelTunables => {
            service.protect_kernel_tunables().await.map(bool_readback)
        }
        SystemdHardeningProperty::ProtectKernelModules => {
            service.protect_kernel_modules().await.map(bool_readback)
        }
        SystemdHardeningProperty::ProtectKernelLogs => {
            service.protect_kernel_logs().await.map(bool_readback)
        }
        SystemdHardeningProperty::ProtectClock => service.protect_clock().await.map(bool_readback),
        SystemdHardeningProperty::ProtectHostname => {
            service.protect_hostname().await.map(bool_readback)
        }
        SystemdHardeningProperty::ProtectProc => service.protect_proc().await.map(string_readback),
        SystemdHardeningProperty::ProcSubset => service.proc_subset().await.map(string_readback),
        SystemdHardeningProperty::RestrictNamespaces => {
            service.restrict_namespaces().await.map(u64_readback)
        }
        SystemdHardeningProperty::RestrictSuidSgid => {
            service.restrict_suidsgid().await.map(bool_readback)
        }
        SystemdHardeningProperty::RestrictRealtime => {
            service.restrict_realtime().await.map(bool_readback)
        }
        SystemdHardeningProperty::LockPersonality => {
            service.lock_personality().await.map(bool_readback)
        }
        SystemdHardeningProperty::SystemCallArchitectures => service
            .system_call_architectures()
            .await
            .map(SystemdHardeningReadbackValue::StringArray),
        SystemdHardeningProperty::UMask => service.u_mask().await.map(u32_readback),
        SystemdHardeningProperty::KillMode => service.kill_mode().await.map(string_readback),
        SystemdHardeningProperty::SendSigKill => service.send_sigkill().await.map(bool_readback),
    }
}

const fn bool_readback(value: bool) -> SystemdHardeningReadbackValue {
    SystemdHardeningReadbackValue::Bool(value)
}

const fn string_readback(value: String) -> SystemdHardeningReadbackValue {
    SystemdHardeningReadbackValue::String(value)
}

const fn u64_readback(value: u64) -> SystemdHardeningReadbackValue {
    SystemdHardeningReadbackValue::U64(value)
}

const fn u32_readback(value: u32) -> SystemdHardeningReadbackValue {
    SystemdHardeningReadbackValue::U32(value)
}

fn encode_property(
    property: SystemdTransientUnitProperty,
) -> Result<(String, OwnedValue), SystemdTransientUnitTransportError> {
    let (name, value) = property.into_parts();
    encode_property_with(name, value, OwnedValue::try_from)
}

fn encode_property_with<O>(
    name: &'static str,
    value: SystemdTransientUnitValue,
    owned_value: O,
) -> Result<(String, OwnedValue), SystemdTransientUnitTransportError>
where
    O: FnOnce(Value<'static>) -> Result<OwnedValue, zvariant::Error>,
{
    owned_value(value.into_dbus_value())
        .map(|value| (name.to_owned(), value))
        .map_err(SystemdTransientUnitTransportError::Serialization)
}

fn classify_call_error(error: zbus::Error) -> SystemdTransientUnitTransportError {
    match error {
        zbus::Error::Variant(error) => SystemdTransientUnitTransportError::Serialization(error),
        error => SystemdTransientUnitTransportError::ManagerCall(error),
    }
}

impl SystemdTransientUnitValue {
    fn into_dbus_value(self) -> Value<'static> {
        match self {
            Self::Static(value) => match value {
                SystemdHardeningValue::Bool(value) => Value::from(value),
                SystemdHardeningValue::String(value) => Value::from(value.to_owned()),
                SystemdHardeningValue::U64(value) => Value::from(value),
                SystemdHardeningValue::U32(value) => Value::from(value),
                SystemdHardeningValue::StringArray(value) => {
                    Value::from(value.iter().map(ToString::to_string).collect::<Vec<_>>())
                }
            },
            Self::RootDirectory(value) => Value::from(value),
            Self::BindReadOnlyPaths(value) => Value::from(value),
            Self::SystemCallFilter(value) | Self::RestrictAddressFamilies(value) => {
                Value::from(value)
            }
            Self::Numeric(value) => match value {
                crate::SystemdTransientUnitNumericValue::OperatingLimit(value) => {
                    Value::from(value)
                }
                crate::SystemdTransientUnitNumericValue::FileDescriptorStoreMax(value) => {
                    Value::from(value)
                }
            },
            Self::ExtraFileDescriptors(value) => extra_file_descriptors_value(value),
        }
    }
}

fn extra_file_descriptors_value(descriptors: Vec<(OwnedFd, String)>) -> Value<'static> {
    let descriptors = descriptors
        .into_iter()
        .map(|(descriptor, name)| (Fd::from(descriptor), name))
        .collect::<Vec<_>>();
    Value::from(descriptors)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
