//! Typed system-bus submission and requested-state verification.

use futures_util::StreamExt;
use zbus::{zvariant::OwnedObjectPath, Connection};
use zbus_systemd::systemd1::{ManagerProxy, ServiceProxy};
use zvariant::{Fd, OwnedFd, OwnedValue, Value};

use crate::{
    transient_unit::SystemdTransientUnitPropertyKind, SystemdHardeningProperty,
    SystemdHardeningReadbackValue, SystemdHardeningValue, SystemdManagerReadback,
    SystemdManagerReadbackOnlyProperty, SystemdTransientUnitProperty, SystemdTransientUnitReadback,
    SystemdTransientUnitReadbackValue, SystemdTransientUnitValue, TransientUnitRequest,
    TransientUnitRequestError,
};

const JOB_MODE: &str = "fail";
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

/// A systemd start-job result that cannot authorize requested-state readback.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SystemdJobFailure {
    /// The job was explicitly cancelled.
    #[error("systemd cancelled the transient-unit start job")]
    Canceled,
    /// The job exceeded its systemd job timeout.
    #[error("the systemd transient-unit start job timed out")]
    Timeout,
    /// The job failed.
    #[error("the systemd transient-unit start job failed")]
    Failed,
    /// A dependency job failed.
    #[error("a dependency of the systemd transient-unit start job failed")]
    Dependency,
    /// systemd skipped the job.
    #[error("systemd skipped the transient-unit start job")]
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

/// Fail-closed failures before or during typed transient-unit submission.
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
        let connection = Connection::system()
            .await
            .map_err(SystemdTransientUnitTransportError::Connect)?;
        Self::from_connection(connection).await
    }

    async fn from_connection(
        connection: Connection,
    ) -> Result<Self, SystemdTransientUnitTransportError> {
        let proxy = ManagerProxy::new(&connection)
            .await
            .map_err(SystemdTransientUnitTransportError::Proxy)?;
        proxy
            .subscribe()
            .await
            .map_err(SystemdTransientUnitTransportError::ManagerSubscribe)?;
        Ok(Self { connection })
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
        let proxy = ManagerProxy::new(&self.connection).await;
        let properties = request
            .requested_properties_for_submission()
            .map_err(SystemdTransientUnitTransportError::Serialization)?
            .into_iter()
            .map(encode_property)
            .collect::<Result<Vec<_>, _>>()?;
        submit_and_verify(proxy, properties, unit_name, &request, &self.connection).await
    }
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
    let mut completions = proxy
        .receive_job_removed()
        .await
        .map_err(SystemdTransientUnitTransportError::JobSignalSubscribe)?;
    let submitted_name = unit_name.0.clone();
    let job_path = match proxy
        .start_transient_unit(
            submitted_name.clone(),
            JOB_MODE.to_owned(),
            properties,
            Vec::new(),
        )
        .await
    {
        Ok(job_path) => job_path,
        Err(error) => return Err(classify_call_error(error)),
    };
    let job = SystemdStartJob(job_path);
    loop {
        let completion = completions
            .next()
            .await
            .ok_or(SystemdTransientUnitTransportError::JobSignalEnded)?;
        let args = completion
            .args()
            .map_err(SystemdTransientUnitTransportError::JobSignal)?;
        if args.job().as_str() != job.as_str() {
            continue;
        }
        if args.unit() != &submitted_name {
            return Err(SystemdTransientUnitTransportError::JobIdentityMismatch {
                expected: submitted_name,
                actual: args.unit().clone(),
            });
        }
        if let Some(failure) = SystemdJobFailure::from_result(args.result().clone()) {
            return Err(failure.into());
        }
        break;
    }
    let unit_path = proxy
        .get_unit(submitted_name)
        .await
        .map_err(SystemdTransientUnitTransportError::UnitLookup)?;
    let service = ServiceProxy::builder(connection)
        .path(unit_path.clone())
        .map_err(SystemdTransientUnitTransportError::ServiceProxy)?
        .build()
        .await
        .map_err(SystemdTransientUnitTransportError::ServiceProxy)?;
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
        SystemdTransientUnitPropertyKind::RootDirectory => service
            .root_directory()
            .await
            .map(SystemdTransientUnitReadbackValue::String),
        SystemdTransientUnitPropertyKind::BindReadOnlyPaths => service
            .bind_read_only_paths()
            .await
            .map(SystemdTransientUnitReadbackValue::BindReadOnlyPaths),
        SystemdTransientUnitPropertyKind::SystemCallFilter => service
            .system_call_filter()
            .await
            .map(SystemdTransientUnitReadbackValue::BoolStringArray),
        SystemdTransientUnitPropertyKind::RestrictAddressFamilies => service
            .restrict_address_families()
            .await
            .map(SystemdTransientUnitReadbackValue::BoolStringArray),
        SystemdTransientUnitPropertyKind::FileDescriptorStoreMax => service
            .file_descriptor_store_max()
            .await
            .map(SystemdTransientUnitReadbackValue::U32),
        SystemdTransientUnitPropertyKind::ExtraFileDescriptors => service
            .extra_file_descriptor_names()
            .await
            .map(SystemdTransientUnitReadbackValue::StringArray),
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
        SystemdHardeningProperty::PrivateMounts => service.private_mounts().await.map(bool_readback),
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
        SystemdHardeningProperty::ProtectControlGroupsEx => {
            service.protect_control_groups_ex().await.map(string_readback)
        }
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
    owned_value(property_value(value))
        .map(|value| (name.to_owned(), value))
        .map_err(SystemdTransientUnitTransportError::Serialization)
}

fn classify_call_error(error: zbus::Error) -> SystemdTransientUnitTransportError {
    match error {
        zbus::Error::Variant(error) => SystemdTransientUnitTransportError::Serialization(error),
        error => SystemdTransientUnitTransportError::ManagerCall(error),
    }
}

fn property_value(value: SystemdTransientUnitValue) -> Value<'static> {
    match value {
        SystemdTransientUnitValue::Static(value) => match value {
            SystemdHardeningValue::Bool(value) => Value::from(value),
            SystemdHardeningValue::String(value) => Value::from(value.to_owned()),
            SystemdHardeningValue::U64(value) => Value::from(value),
            SystemdHardeningValue::U32(value) => Value::from(value),
            SystemdHardeningValue::StringArray(value) => {
                Value::from(value.iter().map(ToString::to_string).collect::<Vec<_>>())
            }
        },
        SystemdTransientUnitValue::RootDirectory(value) => Value::from(value),
        SystemdTransientUnitValue::BindReadOnlyPaths(value) => Value::from(value),
        SystemdTransientUnitValue::SystemCallFilter(value)
        | SystemdTransientUnitValue::RestrictAddressFamilies(value) => Value::from(value),
        SystemdTransientUnitValue::FileDescriptorStoreMax(value) => Value::from(value),
        SystemdTransientUnitValue::ExtraFileDescriptors(value) => {
            extra_file_descriptors_value(value)
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
mod tests;
