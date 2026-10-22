//! Typed dynamic systemd transient-unit launch properties.

use pos_reference::sandbox_provider_protocol::SandboxLimit;
use zvariant::{Fd, OwnedFd};

use crate::{
    SystemCallFilter, SystemdDynamicPropertyKind, SystemdHardeningProperty,
    SystemdHardeningReadbackValue, SystemdHardeningValue, SystemdOperatingLimitProperty,
    SystemdTransientUnitPropertyAccess, SystemdTransientUnitPropertyKind, TransientUnitHardening,
};

const MAX_PROVIDER_PATH_BYTES: usize = 4096;
const LAUNCHER_DESTINATION: &str = "/.pigloros/release-launcher";
const RELEASE_DESCRIPTOR_NAME: &str = "piglor-release-v1";
const HOST_SERVICE_DESCRIPTOR_NAME: &str = "piglor-host-service-v1";
const ELM1_LIMIT_COUNT: usize = 17;
/// ELM1 limit 9 (`WorkBytes`) sizes the one optional writable mount.
const WORK_BYTES_LIMIT_ID: usize = 9;
/// The sole writable mount point (ADR-069 section 6).
const WORK_MOUNT_PATH: &str = "/work";

/// The systemd-owned portion of one complete, already authorized ELM1 limit set.
///
/// This validates representation and preserves exact requested values; it does
/// not authenticate ELM1, grant admission, or prove kernel enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdServiceLimits {
    requested: [u64; 7],
    work_bytes: u64,
}

/// Failure to represent the exact ELM1 service limits on pinned systemd.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SystemdServiceLimitsError {
    /// ELM1 must contain exactly one record for every ID 0 through 16 in order.
    #[error("effective limits are not the complete ordered ELM1 set")]
    InvalidEffectiveLimits,
    /// The specified exact capacity would be rejected or interpreted as infinity.
    #[error("ELM1 limit ID {0} cannot be enforced exactly by systemd")]
    UnenforceableLimit(u8),
    /// The watchdog milliseconds cannot be represented as systemd microseconds.
    #[error("ELM1 watchdog milliseconds overflow systemd microseconds")]
    WatchdogOverflow,
}

impl SystemdServiceLimits {
    /// Compile exact systemd values from one complete, already authorized ELM1.
    ///
    /// The caller must obtain these records from the authenticated provider
    /// admission boundary. This method only checks shape and representability.
    ///
    /// # Errors
    /// Rejects missing, duplicate, unordered, or unknown IDs, values that
    /// systemd rejects or treats as infinity, and watchdog conversion overflow.
    pub fn from_effective_limits(
        limits: &[SandboxLimit],
    ) -> Result<Self, SystemdServiceLimitsError> {
        if limits.len() != ELM1_LIMIT_COUNT
            || limits
                .iter()
                .enumerate()
                .any(|(id, limit)| usize::from(limit.limit_id) != id)
        {
            return Err(SystemdServiceLimitsError::InvalidEffectiveLimits);
        }
        let mut requested = [0; 7];
        let work_bytes = limits[WORK_BYTES_LIMIT_ID].value;
        // tmpfs reads `size=18446744073709551615` as an unbounded mount.
        if work_bytes == u64::MAX {
            return Err(SystemdServiceLimitsError::UnenforceableLimit(
                limits[WORK_BYTES_LIMIT_ID].limit_id,
            ));
        }
        for (id, limit) in limits.iter().take(requested.len()).enumerate() {
            if limit.value == u64::MAX || ([0, 2, 3, 4].contains(&id) && limit.value == 0) {
                return Err(SystemdServiceLimitsError::UnenforceableLimit(
                    limit.limit_id,
                ));
            }
            requested[id] = limit.value;
        }
        requested[4] = requested[4]
            .checked_mul(1_000)
            .ok_or(SystemdServiceLimitsError::WatchdogOverflow)?;
        Ok(Self {
            requested,
            work_bytes,
        })
    }

    /// The requested `TemporaryFileSystem` entries: the `/work` tmpfs sized by
    /// ELM1 `WorkBytes`, or none when that ceiling is zero.
    ///
    /// A zero ceiling is a literal zero-capacity limit, and tmpfs reads
    /// `size=0` as unbounded, so no writable mount is requested at all.
    fn temporary_file_systems(&self) -> Vec<(String, String)> {
        if self.work_bytes == 0 {
            Vec::new()
        } else {
            vec![(
                WORK_MOUNT_PATH.to_owned(),
                format!("size={},nosuid,nodev,noexec", self.work_bytes),
            )]
        }
    }

    pub(crate) const fn value(&self, property: SystemdOperatingLimitProperty) -> u64 {
        self.requested[property.index()]
    }
}

/// A bounded provider-owned path to the activated admitted SIM1 root beneath `/run`.
///
/// It has no public constructor: a [`crate::VerifiedRootMount`] supplies the
/// only one, after kernel readback and re-admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedRootDirectory(String);

impl ActivatedRootDirectory {
    /// Validate one activated-root path representation, for tests only.
    ///
    /// Production roots come solely from [`crate::VerifiedRootMount`] (owner
    /// decision Q9.4), so this constructor does not exist in a build.
    ///
    /// # Errors
    /// Rejects paths outside `/run`, paths with traversal or empty components,
    /// embedded NUL bytes, and paths larger than the Linux path bound.
    #[cfg(test)]
    pub(crate) fn new(path: impl Into<String>) -> Result<Self, TransientUnitRequestError> {
        let path = path.into();
        if is_normalized_absolute_path(&path) && path.starts_with("/run/") {
            Ok(Self(path))
        } else {
            Err(TransientUnitRequestError::InvalidRootDirectory)
        }
    }

    /// The fixed attempt root `/run/pigloros/sandbox/attempts/<component>/root`.
    ///
    /// `component` is the validated 32-hex attempt component of a
    /// [`crate::TransientServiceUnitName`], so the path is always valid.
    #[cfg(target_os = "linux")]
    pub(crate) fn for_attempt(component: &str) -> Self {
        Self(format!("/run/pigloros/sandbox/attempts/{component}/root"))
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

/// The verified attempt root, rechecked immediately before launch (ADR-087
/// §2 step 7).
///
/// It has no public constructor. Only [`crate::VerifiedRootMount::recheck`]
/// mints one, after current RVS1, the control floor and the attached mount
/// identity were checked again, and [`TransientUnitLaunchInputs`] accepts
/// nothing else as `RootDirectory`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedRoot {
    root_directory: ActivatedRootDirectory,
}

impl CheckedRoot {
    #[cfg(target_os = "linux")]
    pub(crate) const fn rechecked(root_directory: ActivatedRootDirectory) -> Self {
        Self { root_directory }
    }

    /// A rechecked root for requested-state unit tests, where no mount exists.
    #[cfg(test)]
    pub(crate) const fn for_test(root_directory: ActivatedRootDirectory) -> Self {
        Self { root_directory }
    }
}

impl TransientUnitLaunchInputs {
    /// Combine a rechecked root with the other per-attempt launch inputs.
    #[must_use]
    pub fn new(
        root: &CheckedRoot,
        launcher_source: LauncherSource,
        mode: LaunchMode,
        release: OwnedFd,
    ) -> Self {
        Self {
            root_directory: root.root_directory.clone(),
            launcher_source,
            mode,
            release,
        }
    }
}

/// An exact D-Bus numeric requested-state value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdTransientUnitNumericValue {
    /// One exact ELM1-derived D-Bus `t` service limit.
    OperatingLimit(u64),
    /// A D-Bus `u` descriptor-store limit.
    FileDescriptorStoreMax(u32),
}

impl SystemdTransientUnitNumericValue {
    const fn dbus_signature(self) -> &'static str {
        match self {
            Self::OperatingLimit(_) => "t",
            Self::FileDescriptorStoreMax(_) => "u",
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
    /// A D-Bus `t` or `u` numeric property with its exact semantic type.
    Numeric(SystemdTransientUnitNumericValue),
    /// A D-Bus `a(hs)` descriptor array: Unix FD before descriptor name.
    ExtraFileDescriptors(Vec<(OwnedFd, String)>),
    /// A D-Bus `a(ss)` array of tmpfs mount path and mount options.
    TemporaryFileSystem(Vec<(String, String)>),
}

impl SystemdTransientUnitValue {
    fn try_clone_for_submission(&self) -> Result<Self, zvariant::Error> {
        match self {
            Self::Static(value) => Ok(Self::Static(*value)),
            Self::RootDirectory(value) => Ok(Self::RootDirectory(value.clone())),
            Self::BindReadOnlyPaths(value) => Ok(Self::BindReadOnlyPaths(value.clone())),
            Self::SystemCallFilter(value) => Ok(Self::SystemCallFilter(value.clone())),
            Self::RestrictAddressFamilies(value) => {
                Ok(Self::RestrictAddressFamilies(value.clone()))
            }
            Self::Numeric(value) => Ok(Self::Numeric(*value)),
            Self::ExtraFileDescriptors(value) => value
                .iter()
                .map(|(descriptor, name)| {
                    let descriptor = Fd::from(descriptor).try_to_owned().map(OwnedFd::from)?;
                    Ok((descriptor, name.clone()))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Self::ExtraFileDescriptors),
            Self::TemporaryFileSystem(value) => Ok(Self::TemporaryFileSystem(value.clone())),
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

    /// Return the exact D-Bus signature for this named requested property.
    #[must_use]
    pub const fn dbus_signature(&self) -> &'static str {
        match &self.value {
            SystemdTransientUnitValue::Static(value) => value.dbus_signature(),
            SystemdTransientUnitValue::RootDirectory(_) => "s",
            SystemdTransientUnitValue::BindReadOnlyPaths(_) => "a(ssbt)",
            SystemdTransientUnitValue::SystemCallFilter(_)
            | SystemdTransientUnitValue::RestrictAddressFamilies(_) => "(bas)",
            SystemdTransientUnitValue::Numeric(value) => value.dbus_signature(),
            SystemdTransientUnitValue::ExtraFileDescriptors(_) => "a(hs)",
            SystemdTransientUnitValue::TemporaryFileSystem(_) => "a(ss)",
        }
    }

    fn readback_matches(
        &self,
        observed: &SystemdTransientUnitReadback,
        system_call_filter: &SystemCallFilter,
    ) -> bool {
        observed.name == self.name()
            && match (&self.value, &observed.value) {
                (
                    SystemdTransientUnitValue::Numeric(
                        SystemdTransientUnitNumericValue::FileDescriptorStoreMax(expected),
                    ),
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
                ) => system_call_filter.verify_readback(actual).is_ok(),
                (
                    SystemdTransientUnitValue::RestrictAddressFamilies(expected),
                    SystemdTransientUnitReadbackValue::BoolStringArray(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::Numeric(
                        SystemdTransientUnitNumericValue::OperatingLimit(expected),
                    ),
                    SystemdTransientUnitReadbackValue::U64(actual),
                ) => expected == actual,
                (
                    SystemdTransientUnitValue::ExtraFileDescriptors(expected),
                    SystemdTransientUnitReadbackValue::StringArray(actual),
                ) => expected.iter().map(|(_, name)| name).eq(actual.iter()),
                (
                    SystemdTransientUnitValue::TemporaryFileSystem(expected),
                    SystemdTransientUnitReadbackValue::TemporaryFileSystem(actual),
                ) => expected == actual,
                _ => false,
            }
    }

    fn try_clone_for_submission(&self) -> Result<Self, zvariant::Error> {
        Self::from_cloned_value(self.kind, self.value.try_clone_for_submission())
    }

    fn from_cloned_value(
        kind: SystemdTransientUnitPropertyKind,
        value: Result<SystemdTransientUnitValue, zvariant::Error>,
    ) -> Result<Self, zvariant::Error> {
        Ok(Self {
            kind,
            value: value?,
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
    /// A D-Bus `a(ss)` value.
    TemporaryFileSystem(Vec<(String, String)>),
    /// A D-Bus `u` value.
    U32(u32),
    /// A D-Bus `t` value.
    U64(u64),
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
/// It composes static hardening, selected SCS1 syscall filtering, exact ELM1
/// service limits, and per-attempt dynamic fields without a D-Bus connection,
/// process execution, descriptor acquisition, or admission decision.
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
        service_limits: &SystemdServiceLimits,
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
            Vec::with_capacity(TransientUnitHardening::requested_properties().len() + 14);
        for property in TransientUnitHardening::requested_properties() {
            properties.push(SystemdTransientUnitProperty::new(
                SystemdTransientUnitPropertyKind::Hardening(*property),
                SystemdTransientUnitValue::Static(property.value()),
            ));
            if *property == SystemdHardeningProperty::TypeExec {
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::Dynamic(
                        SystemdDynamicPropertyKind::RootDirectory,
                    ),
                    SystemdTransientUnitValue::RootDirectory(root_directory.as_str().to_owned()),
                ));
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::Dynamic(
                        SystemdDynamicPropertyKind::BindReadOnlyPaths,
                    ),
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
                    SystemdTransientUnitPropertyKind::Dynamic(
                        SystemdDynamicPropertyKind::SystemCallFilter,
                    ),
                    SystemdTransientUnitValue::SystemCallFilter(
                        system_call_filter.requested_property(),
                    ),
                ));
                properties.push(SystemdTransientUnitProperty::new(
                    SystemdTransientUnitPropertyKind::Dynamic(
                        SystemdDynamicPropertyKind::RestrictAddressFamilies,
                    ),
                    SystemdTransientUnitValue::RestrictAddressFamilies(address_families.clone()),
                ));
            }
        }
        properties.extend(SystemdOperatingLimitProperty::ALL.map(|limit| {
            SystemdTransientUnitProperty::new(
                SystemdTransientUnitPropertyKind::Dynamic(
                    SystemdDynamicPropertyKind::OperatingLimit(limit),
                ),
                SystemdTransientUnitValue::Numeric(
                    SystemdTransientUnitNumericValue::OperatingLimit(service_limits.value(limit)),
                ),
            )
        }));
        properties.push(SystemdTransientUnitProperty::new(
            SystemdTransientUnitPropertyKind::Dynamic(
                SystemdDynamicPropertyKind::FileDescriptorStoreMax,
            ),
            SystemdTransientUnitValue::Numeric(
                SystemdTransientUnitNumericValue::FileDescriptorStoreMax(0),
            ),
        ));
        properties.push(SystemdTransientUnitProperty::new(
            SystemdTransientUnitPropertyKind::Dynamic(
                SystemdDynamicPropertyKind::ExtraFileDescriptors,
            ),
            SystemdTransientUnitValue::ExtraFileDescriptors(descriptors),
        ));
        properties.push(SystemdTransientUnitProperty::new(
            SystemdTransientUnitPropertyKind::Dynamic(
                SystemdDynamicPropertyKind::TemporaryFileSystem,
            ),
            SystemdTransientUnitValue::TemporaryFileSystem(service_limits.temporary_file_systems()),
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
                .all(|(observed, requested)| {
                    requested.readback_matches(observed, &self.system_call_filter)
                })
        {
            Ok(())
        } else {
            Err(TransientUnitRequestError::ReadbackMismatch)
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
