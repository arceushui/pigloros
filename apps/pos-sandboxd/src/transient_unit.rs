//! Typed dynamic systemd transient-unit launch properties.

use zvariant::{Fd, OwnedFd};

use crate::{
    SystemCallFilter, SystemdHardeningProperty, SystemdHardeningReadbackValue,
    SystemdHardeningValue, SystemdTransientUnitPropertyAccess, SystemdTransientUnitPropertyKind,
    TransientUnitHardening,
};

const MAX_PROVIDER_PATH_BYTES: usize = 4096;
const LAUNCHER_DESTINATION: &str = "/.pigloros/release-launcher";
const RELEASE_DESCRIPTOR_NAME: &str = "piglor-release-v1";
const HOST_SERVICE_DESCRIPTOR_NAME: &str = "piglor-host-service-v1";

/// A bounded provider-owned path to the activated admitted SIM1 root beneath `/run`.
///
/// Construction validates only the path representation. The provider activation
/// boundary remains responsible for ownership, freshness, and the read-only mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedRootDirectory(String);

impl ActivatedRootDirectory {
    /// Validate one provider-owned activated-root path.
    ///
    /// # Errors
    /// Rejects paths outside `/run`, paths with traversal or empty components,
    /// embedded NUL bytes, and paths larger than the Linux path bound.
    pub fn new(path: impl Into<String>) -> Result<Self, TransientUnitRequestError> {
        let path = path.into();
        if is_normalized_absolute_path(&path) && path.starts_with("/run/") {
            Ok(Self(path))
        } else {
            Err(TransientUnitRequestError::InvalidRootDirectory)
        }
    }

    /// Return the exact D-Bus `s` value for `RootDirectory`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded provider-owned source path for the admitted launcher bind mount.
///
/// The provider's launcher-admission boundary owns source identity, ownership,
/// immutability, and digest validation; this type keeps only its normalized path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherSource(String);

impl LauncherSource {
    /// Validate one launcher source path supplied by the provider boundary.
    ///
    /// # Errors
    /// Rejects non-absolute, non-normalized, embedded-NUL, or oversized paths.
    pub fn new(path: impl Into<String>) -> Result<Self, TransientUnitRequestError> {
        let path = path.into();
        if is_normalized_absolute_path(&path) {
            Ok(Self(path))
        } else {
            Err(TransientUnitRequestError::InvalidLauncherSource)
        }
    }

    /// Return the exact source for `BindReadOnlyPaths`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed ADR-069 execution mode and any mode-specific descriptor.
///
/// Only Local can carry a host-service proxy descriptor. All other modes are
/// structurally unable to add one.
#[derive(Debug)]
pub enum LaunchMode {
    /// Local execution with the host-service proxy descriptor.
    Local { host_service: OwnedFd },
    /// Air-Gapped execution without a host-service descriptor.
    AirGapped,
    /// Replay execution without a host-service descriptor.
    Replay,
    /// Fork execution without a host-service descriptor.
    Fork,
}

/// All per-attempt inputs that the dynamic property compiler is allowed to use.
///
/// The release descriptor is supplied by the existing release-barrier owner.
/// This type neither acquires descriptors nor starts a transient unit.
#[derive(Debug)]
pub struct TransientUnitLaunchInputs {
    root_directory: ActivatedRootDirectory,
    launcher_source: LauncherSource,
    mode: LaunchMode,
    release: OwnedFd,
}

impl TransientUnitLaunchInputs {
    /// Combine already-validated per-attempt launch inputs.
    #[must_use]
    pub const fn new(
        root_directory: ActivatedRootDirectory,
        launcher_source: LauncherSource,
        mode: LaunchMode,
        release: OwnedFd,
    ) -> Self {
        Self {
            root_directory,
            launcher_source,
            mode,
            release,
        }
    }
}

/// One D-Bus requested-state value in the closed transient-unit bundle.
#[derive(Debug)]
pub enum SystemdTransientUnitValue {
    /// One fixed static hardening value.
    Static(SystemdHardeningValue),
    /// A D-Bus `s` root-directory value.
    RootDirectory(String),
    /// A D-Bus `a(ssbt)` launcher bind-mount value.
    BindReadOnlyPaths(Vec<(String, String, bool, u64)>),
    /// A D-Bus `(bas)` syscall-filter value.
    SystemCallFilter((bool, Vec<String>)),
    /// A D-Bus `(bas)` address-family value.
    RestrictAddressFamilies((bool, Vec<String>)),
    /// A D-Bus `u` descriptor-store limit.
    FileDescriptorStoreMax(u32),
    /// A D-Bus `a(hs)` descriptor array: Unix FD before descriptor name.
    ExtraFileDescriptors(Vec<(OwnedFd, String)>),
}

impl SystemdTransientUnitValue {
    /// Return the exact D-Bus signature for this requested value.
    #[must_use]
    pub const fn dbus_signature(&self) -> &'static str {
        match self {
            Self::Static(value) => value.dbus_signature(),
            Self::RootDirectory(_) => "s",
            Self::BindReadOnlyPaths(_) => "a(ssbt)",
            Self::SystemCallFilter(_) | Self::RestrictAddressFamilies(_) => "(bas)",
            Self::FileDescriptorStoreMax(_) => "u",
            Self::ExtraFileDescriptors(_) => "a(hs)",
        }
    }

    fn try_clone_for_submission(&self) -> Result<Self, zvariant::Error> {
        match self {
            Self::Static(value) => Ok(Self::Static(*value)),
            Self::RootDirectory(value) => Ok(Self::RootDirectory(value.clone())),
            Self::BindReadOnlyPaths(value) => Ok(Self::BindReadOnlyPaths(value.clone())),
            Self::SystemCallFilter(value) => Ok(Self::SystemCallFilter(value.clone())),
            Self::RestrictAddressFamilies(value) => {
                Ok(Self::RestrictAddressFamilies(value.clone()))
            }
            Self::FileDescriptorStoreMax(value) => Ok(Self::FileDescriptorStoreMax(*value)),
            Self::ExtraFileDescriptors(value) => value
                .iter()
                .map(|(descriptor, name)| {
                    let descriptor = Fd::from(descriptor).try_to_owned().map(OwnedFd::from)?;
                    Ok((descriptor, name.clone()))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self::ExtraFileDescriptors),
        }
    }
}

/// One named typed property ready for `StartTransientUnit` serialization.
#[derive(Debug)]
pub struct SystemdTransientUnitProperty {
    kind: SystemdTransientUnitPropertyKind,
    value: SystemdTransientUnitValue,
}

impl SystemdTransientUnitProperty {
    const fn new(kind: SystemdTransientUnitPropertyKind, value: SystemdTransientUnitValue) -> Self {
        Self { kind, value }
    }

    /// Return the exact systemd property name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.kind.name()
    }

    /// Return the typed property value.
    #[must_use]
    pub const fn value(&self) -> &SystemdTransientUnitValue {
        &self.value
    }

    fn try_clone_for_submission(&self) -> Result<Self, zvariant::Error> {
        Ok(Self {
            kind: self.kind,
            value: self.value.try_clone_for_submission()?,
        })
    }
}

impl SystemdTransientUnitPropertyAccess for SystemdTransientUnitProperty {
    fn kind(&self) -> SystemdTransientUnitPropertyKind {
        self.kind
    }

    fn into_parts(self) -> (&'static str, SystemdTransientUnitValue) {
        (self.kind.name(), self.value)
    }
}

/// A typed observed transient-unit property used by the request verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdTransientUnitReadback {
    name: String,
    value: SystemdTransientUnitReadbackValue,
}

/// One manager-only property observed separately from the requested bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdManagerReadback {
    property: SystemdManagerReadbackOnlyProperty,
    value: String,
}

impl SystemdManagerReadback {
    /// Record one typed effective manager default without making it a request.
    #[must_use]
    pub fn new(property: SystemdManagerReadbackOnlyProperty, value: impl Into<String>) -> Self {
        Self {
            property,
            value: value.into(),
        }
    }

    /// Return the observed manager-only property identity.
    #[must_use]
    pub const fn property(&self) -> SystemdManagerReadbackOnlyProperty {
        self.property
    }

    /// Return the observed manager-default D-Bus `s` value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl SystemdTransientUnitReadback {
    /// Construct one typed manager readback property.
    #[must_use]
    pub fn new(name: impl Into<String>, value: SystemdTransientUnitReadbackValue) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// Return the exact systemd property name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the typed observed value.
    #[must_use]
    pub const fn value(&self) -> &SystemdTransientUnitReadbackValue {
        &self.value
    }
}

/// One permitted typed manager readback value for the dynamic request verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemdTransientUnitReadbackValue {
    /// One static hardening value with its exact D-Bus type.
    Static(SystemdHardeningReadbackValue),
    /// A D-Bus `s` value.
    String(String),
    /// A D-Bus `a(ssbt)` value.
    BindReadOnlyPaths(Vec<(String, String, bool, u64)>),
    /// A D-Bus `(bas)` value.
    BoolStringArray((bool, Vec<String>)),
    /// A D-Bus `as` value.
    StringArray(Vec<String>),
    /// A D-Bus `u` value.
    U32(u32),
}

/// A manager property that is observed but never sent in this request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdManagerReadbackOnlyProperty {
    /// Systemd's inert effective default when no `RootImage` is requested.
    RootImagePolicy,
}

impl SystemdManagerReadbackOnlyProperty {
    /// Return the manager property name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RootImagePolicy => "RootImagePolicy",
        }
    }

    /// Return the required observed D-Bus signature.
    #[must_use]
    pub const fn dbus_signature(self) -> &'static str {
        match self {
            Self::RootImagePolicy => "s",
        }
    }
}

/// Closed failures at the dynamic transient-unit property boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransientUnitRequestError {
    /// The activated root path is outside the closed provider-owned path form.
    #[error("activated root directory is not a bounded normalized /run path")]
    InvalidRootDirectory,
    /// The launcher source is outside the closed provider-owned path form.
    #[error("launcher source is not a bounded normalized absolute path")]
    InvalidLauncherSource,
    /// Observed properties differ from the exact dynamic requested-state contract.
    #[error("systemd transient-unit dynamic readback differs from the prescribed bundle")]
    ReadbackMismatch,
}

/// One complete typed systemd transient-unit request.
///
/// It composes static hardening, selected SCS1 syscall filtering, and the
/// per-attempt dynamic fields without a D-Bus connection, process execution,
/// descriptor acquisition, or admission decision.
pub struct TransientUnitRequest {
    properties: Vec<SystemdTransientUnitProperty>,
    system_call_filter: SystemCallFilter,
}

impl TransientUnitRequest {
    /// Compile one deterministic closed transient-unit property bundle.
    #[must_use]
    pub fn compile(
        inputs: TransientUnitLaunchInputs,
        system_call_filter: SystemCallFilter,
    ) -> Self {
        let TransientUnitLaunchInputs {
            root_directory,
            launcher_source,
            mode,
            release,
        } = inputs;
        let (address_families, descriptors) = match mode {
            LaunchMode::Local { host_service } => (
                (true, vec!["AF_UNIX".to_owned()]),
                vec![
                    (host_service, HOST_SERVICE_DESCRIPTOR_NAME.to_owned()),
                    (release, RELEASE_DESCRIPTOR_NAME.to_owned()),
                ],
            ),
            LaunchMode::AirGapped | LaunchMode::Replay | LaunchMode::Fork => (
                (true, Vec::new()),
                vec![(release, RELEASE_DESCRIPTOR_NAME.to_owned())],
            ),
        };
        let mut properties =
            Vec::with_capacity(TransientUnitHardening::requested_properties().len() + 6);
        for property in TransientUnitHardening::requested_properties() {
            properties.push(SystemdTransientUnitProperty::new(
                SystemdTransientUnitPropertyKind::Hardening(*property),
                SystemdTransientUnitValue::Static(property.value()),
            ));
            if *property == SystemdHardeningProperty::TypeExec {
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::RootDirectory,
                    SystemdTransientUnitValue::RootDirectory(root_directory.as_str().to_owned()),
                ));
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::BindReadOnlyPaths,
                    SystemdTransientUnitValue::BindReadOnlyPaths(vec![(
                        launcher_source.as_str().to_owned(),
                        LAUNCHER_DESTINATION.to_owned(),
                        false,
                        0,
                    )]),
                ));
            }
            if *property == SystemdHardeningProperty::SystemCallArchitectures {
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::SystemCallFilter,
                    SystemdTransientUnitValue::SystemCallFilter(
                        system_call_filter.requested_property(),
                    ),
                ));
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::RestrictAddressFamilies,
                    SystemdTransientUnitValue::RestrictAddressFamilies(address_families.clone()),
                ));
            }
        }
        properties.push(SystemdTransientUnitProperty::new(
            SystemdTransientUnitPropertyKind::FileDescriptorStoreMax,
            SystemdTransientUnitValue::FileDescriptorStoreMax(0),
        ));
        properties.push(SystemdTransientUnitProperty::new(
            SystemdTransientUnitPropertyKind::ExtraFileDescriptors,
            SystemdTransientUnitValue::ExtraFileDescriptors(descriptors),
        ));
        Self {
            properties,
            system_call_filter,
        }
    }

    /// Return the complete ordered requested-state property sequence.
    #[must_use]
    pub fn requested_properties(&self) -> &[SystemdTransientUnitProperty] {
        &self.properties
    }

    pub(crate) fn requested_properties_for_submission(
        &self,
    ) -> Result<Vec<SystemdTransientUnitProperty>, zvariant::Error> {
        self.properties
            .iter()
            .map(SystemdTransientUnitProperty::try_clone_for_submission)
            .collect()
    }

    /// Verify complete ordered typed manager readback for this compiled request.
    ///
    /// `RootImagePolicy` is intentionally absent because it is manager readback
    /// only, never a requested property or signature-admission evidence.
    ///
    /// # Errors
    /// Rejects missing, extra, reordered, renamed, mistyped, or substituted
    /// dynamic properties before a later execution or release transition.
    pub fn verify_readback(
        &self,
        readback: &[SystemdTransientUnitReadback],
    ) -> Result<(), TransientUnitRequestError> {
        if readback.len() == self.properties.len()
            && readback
                .iter()
                .zip(&self.properties)
                .all(|(observed, requested)| self.readback_matches(observed, requested))
        {
            Ok(())
        } else {
            Err(TransientUnitRequestError::ReadbackMismatch)
        }
    }

    fn readback_matches(
        &self,
        observed: &SystemdTransientUnitReadback,
        requested: &SystemdTransientUnitProperty,
    ) -> bool {
        observed.name == requested.name()
            && match (&requested.value, &observed.value) {
                (
                    SystemdTransientUnitValue::FileDescriptorStoreMax(expected),
                    SystemdTransientUnitReadbackValue::U32(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::Static(expected),
                    SystemdTransientUnitReadbackValue::Static(actual),
                ) => actual == &SystemdHardeningReadbackValue::from(*expected),
                (
                    SystemdTransientUnitValue::RootDirectory(expected),
                    SystemdTransientUnitReadbackValue::String(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::BindReadOnlyPaths(expected),
                    SystemdTransientUnitReadbackValue::BindReadOnlyPaths(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::SystemCallFilter(_),
                    SystemdTransientUnitReadbackValue::BoolStringArray(actual),
                ) => self.system_call_filter.verify_readback(actual).is_ok(),
                (
                    SystemdTransientUnitValue::RestrictAddressFamilies(expected),
                    SystemdTransientUnitReadbackValue::BoolStringArray(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::ExtraFileDescriptors(expected),
                    SystemdTransientUnitReadbackValue::StringArray(actual),
                ) => expected.iter().map(|(_, name)| name).eq(actual.iter()),
                _ => false,
            }
    }
}

fn is_normalized_absolute_path(path: &str) -> bool {
    path.len() < MAX_PROVIDER_PATH_BYTES
        && path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}
