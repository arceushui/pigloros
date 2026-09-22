//! Typed system-bus submission of compiled transient-unit requests.

use zbus::{zvariant::OwnedObjectPath, Connection};
use zvariant::{Fd, OwnedFd, OwnedValue, Value};

use crate::{
    SystemdHardeningValue, SystemdTransientUnitProperty, SystemdTransientUnitValue,
    TransientUnitRequest,
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

/// Fail-closed failures before or during typed transient-unit submission.
#[derive(Debug, thiserror::Error)]
pub enum SystemdTransientUnitTransportError {
    /// The process could not establish its privileged system-bus connection.
    #[error("failed to connect to the system D-Bus")]
    Connect(#[source] zbus::Error),
    /// The generated systemd manager proxy could not be constructed.
    #[error("failed to construct the typed systemd manager proxy")]
    Proxy(#[source] zbus::Error),
    /// One closed request value could not be serialized for D-Bus.
    #[error("failed to serialize the typed transient-unit request")]
    Serialization(#[source] zvariant::Error),
    /// systemd rejected or failed the typed `StartTransientUnit` call.
    #[error("systemd rejected the transient-unit request")]
    ManagerCall(#[source] zbus::Error),
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
        Connection::system()
            .await
            .map(|connection| Self { connection })
            .map_err(SystemdTransientUnitTransportError::Connect)
    }

    /// Submit one complete compiled request through generated systemd bindings.
    ///
    /// Success proves only that systemd returned a typed job identity. It does not
    /// establish property readback, launcher readiness, release, or enforcement.
    ///
    /// # Errors
    /// Returns a classified proxy, serialization, or manager-call failure.
    pub async fn start(
        &self,
        unit_name: TransientServiceUnitName,
        request: TransientUnitRequest,
    ) -> Result<SystemdStartJob, SystemdTransientUnitTransportError> {
        let proxy = zbus_systemd::systemd1::ManagerProxy::new(&self.connection).await;
        let properties = request
            .into_requested_properties()
            .into_iter()
            .map(encode_property)
            .collect::<Result<Vec<_>, _>>();
        submit(proxy, properties, unit_name).await
    }
}

async fn submit(
    proxy: Result<zbus_systemd::systemd1::ManagerProxy<'_>, zbus::Error>,
    properties: Result<Vec<(String, OwnedValue)>, SystemdTransientUnitTransportError>,
    unit_name: TransientServiceUnitName,
) -> Result<SystemdStartJob, SystemdTransientUnitTransportError> {
    let properties = match properties {
        Ok(properties) => properties,
        Err(error) => return Err(error),
    };
    let proxy = match proxy {
        Ok(proxy) => proxy,
        Err(error) => return Err(SystemdTransientUnitTransportError::Proxy(error)),
    };
    let job_path = match proxy
        .start_transient_unit(unit_name.0, JOB_MODE.to_owned(), properties, Vec::new())
        .await
    {
        Ok(job_path) => job_path,
        Err(error) => return Err(classify_call_error(error)),
    };
    Ok(SystemdStartJob(job_path))
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
