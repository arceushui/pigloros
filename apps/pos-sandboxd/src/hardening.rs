//! Closed systemd transient-unit hardening requested state.

/// One fixed typed systemd property from the ADR-069 static hardening bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdHardeningProperty {
    /// `Type: s = exec`.
    TypeExec,
    /// `DynamicUser: b = true`.
    DynamicUser,
    /// `NoNewPrivileges: b = true`.
    NoNewPrivileges,
    /// `PrivateDevices: b = true`.
    PrivateDevices,
    /// `PrivateIPC: b = true`.
    PrivateIpc,
    /// `PrivateMounts: b = true`.
    PrivateMounts,
    /// `PrivateNetwork: b = true`.
    PrivateNetwork,
    /// `PrivatePIDs: s = yes`.
    PrivatePids,
    /// `PrivateUsersEx: s = self`.
    PrivateUsersEx,
    /// `CapabilityBoundingSet: t = 0`.
    CapabilityBoundingSet,
    /// `AmbientCapabilities: t = 0`.
    AmbientCapabilities,
    /// `ProtectSystem: s = strict`.
    ProtectSystem,
    /// `ProtectHome: s = yes`.
    ProtectHome,
    /// `ProtectControlGroupsEx: s = strict`.
    ProtectControlGroupsEx,
    /// `ProtectKernelTunables: b = true`.
    ProtectKernelTunables,
    /// `ProtectKernelModules: b = true`.
    ProtectKernelModules,
    /// `ProtectKernelLogs: b = true`.
    ProtectKernelLogs,
    /// `ProtectClock: b = true`.
    ProtectClock,
    /// `ProtectHostname: b = true`.
    ProtectHostname,
    /// `ProtectProc: s = invisible`.
    ProtectProc,
    /// `ProcSubset: s = pid`.
    ProcSubset,
    /// `RestrictNamespaces: t = 0x7e020080`.
    RestrictNamespaces,
    /// `RestrictSUIDSGID: b = true`.
    RestrictSuidSgid,
    /// `RestrictRealtime: b = true`.
    RestrictRealtime,
    /// `LockPersonality: b = true`.
    LockPersonality,
    /// `SystemCallArchitectures: as = [native]`.
    SystemCallArchitectures,
    /// `UMask: u = 0077`.
    UMask,
    /// `KillMode: s = control-group`.
    KillMode,
    /// `SendSIGKILL: b = true`.
    SendSigKill,
}

/// A systemd D-Bus value with one of the exact signatures this bundle permits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdHardeningValue {
    /// A D-Bus `b` value.
    Bool(bool),
    /// A D-Bus `s` value.
    String(&'static str),
    /// A D-Bus `t` value.
    U64(u64),
    /// A D-Bus `u` value.
    U32(u32),
    /// A D-Bus `as` value.
    StringArray(&'static [&'static str]),
}

impl SystemdHardeningValue {
    /// Return the exact D-Bus signature for this value.
    #[must_use]
    pub const fn dbus_signature(self) -> &'static str {
        match self {
            Self::Bool(_) => "b",
            Self::String(_) => "s",
            Self::U64(_) => "t",
            Self::U32(_) => "u",
            Self::StringArray(_) => "as",
        }
    }
}

impl SystemdHardeningProperty {
    /// Return this property's systemd D-Bus name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TypeExec => "Type",
            Self::DynamicUser => "DynamicUser",
            Self::NoNewPrivileges => "NoNewPrivileges",
            Self::PrivateDevices => "PrivateDevices",
            Self::PrivateIpc => "PrivateIPC",
            Self::PrivateMounts => "PrivateMounts",
            Self::PrivateNetwork => "PrivateNetwork",
            Self::PrivatePids => "PrivatePIDs",
            Self::PrivateUsersEx => "PrivateUsersEx",
            Self::CapabilityBoundingSet => "CapabilityBoundingSet",
            Self::AmbientCapabilities => "AmbientCapabilities",
            Self::ProtectSystem => "ProtectSystem",
            Self::ProtectHome => "ProtectHome",
            Self::ProtectControlGroupsEx => "ProtectControlGroupsEx",
            Self::ProtectKernelTunables => "ProtectKernelTunables",
            Self::ProtectKernelModules => "ProtectKernelModules",
            Self::ProtectKernelLogs => "ProtectKernelLogs",
            Self::ProtectClock => "ProtectClock",
            Self::ProtectHostname => "ProtectHostname",
            Self::ProtectProc => "ProtectProc",
            Self::ProcSubset => "ProcSubset",
            Self::RestrictNamespaces => "RestrictNamespaces",
            Self::RestrictSuidSgid => "RestrictSUIDSGID",
            Self::RestrictRealtime => "RestrictRealtime",
            Self::LockPersonality => "LockPersonality",
            Self::SystemCallArchitectures => "SystemCallArchitectures",
            Self::UMask => "UMask",
            Self::KillMode => "KillMode",
            Self::SendSigKill => "SendSIGKILL",
        }
    }

    /// Return this property's fixed typed D-Bus value.
    #[must_use]
    pub const fn value(self) -> SystemdHardeningValue {
        match self {
            Self::TypeExec => SystemdHardeningValue::String("exec"),
            Self::DynamicUser
            | Self::NoNewPrivileges
            | Self::PrivateDevices
            | Self::PrivateIpc
            | Self::PrivateMounts
            | Self::PrivateNetwork
            | Self::ProtectKernelTunables
            | Self::ProtectKernelModules
            | Self::ProtectKernelLogs
            | Self::ProtectClock
            | Self::ProtectHostname
            | Self::RestrictSuidSgid
            | Self::RestrictRealtime
            | Self::LockPersonality
            | Self::SendSigKill => SystemdHardeningValue::Bool(true),
            Self::PrivatePids | Self::ProtectHome => SystemdHardeningValue::String("yes"),
            Self::PrivateUsersEx => SystemdHardeningValue::String("self"),
            Self::CapabilityBoundingSet | Self::AmbientCapabilities => {
                SystemdHardeningValue::U64(0)
            }
            Self::ProtectSystem | Self::ProtectControlGroupsEx => {
                SystemdHardeningValue::String("strict")
            }
            Self::ProtectProc => SystemdHardeningValue::String("invisible"),
            Self::ProcSubset => SystemdHardeningValue::String("pid"),
            Self::RestrictNamespaces => SystemdHardeningValue::U64(0x7e02_0080),
            Self::SystemCallArchitectures => SystemdHardeningValue::StringArray(&["native"]),
            Self::UMask => SystemdHardeningValue::U32(0o077),
            Self::KillMode => SystemdHardeningValue::String("control-group"),
        }
    }
}

/// Closed failures at the static hardening readback seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransientUnitHardeningError {
    /// The typed property sequence differs from the prescribed hardening bundle.
    #[error("systemd transient-unit hardening readback differs from the prescribed bundle")]
    ReadbackMismatch,
}

/// The immutable static portion of the ADR-069 transient-unit property bundle.
pub struct TransientUnitHardening;

impl TransientUnitHardening {
    const REQUESTED_PROPERTIES: [SystemdHardeningProperty; 29] = [
        SystemdHardeningProperty::TypeExec,
        SystemdHardeningProperty::DynamicUser,
        SystemdHardeningProperty::NoNewPrivileges,
        SystemdHardeningProperty::PrivateDevices,
        SystemdHardeningProperty::PrivateIpc,
        SystemdHardeningProperty::PrivateMounts,
        SystemdHardeningProperty::PrivateNetwork,
        SystemdHardeningProperty::PrivatePids,
        SystemdHardeningProperty::PrivateUsersEx,
        SystemdHardeningProperty::CapabilityBoundingSet,
        SystemdHardeningProperty::AmbientCapabilities,
        SystemdHardeningProperty::ProtectSystem,
        SystemdHardeningProperty::ProtectHome,
        SystemdHardeningProperty::ProtectControlGroupsEx,
        SystemdHardeningProperty::ProtectKernelTunables,
        SystemdHardeningProperty::ProtectKernelModules,
        SystemdHardeningProperty::ProtectKernelLogs,
        SystemdHardeningProperty::ProtectClock,
        SystemdHardeningProperty::ProtectHostname,
        SystemdHardeningProperty::ProtectProc,
        SystemdHardeningProperty::ProcSubset,
        SystemdHardeningProperty::RestrictNamespaces,
        SystemdHardeningProperty::RestrictSuidSgid,
        SystemdHardeningProperty::RestrictRealtime,
        SystemdHardeningProperty::LockPersonality,
        SystemdHardeningProperty::SystemCallArchitectures,
        SystemdHardeningProperty::UMask,
        SystemdHardeningProperty::KillMode,
        SystemdHardeningProperty::SendSigKill,
    ];

    /// Return the complete ordered static requested-state bundle.
    #[must_use]
    pub const fn requested_properties() -> &'static [SystemdHardeningProperty] {
        &Self::REQUESTED_PROPERTIES
    }

    /// Verify complete ordered typed static-property readback.
    ///
    /// Dynamic root, descriptor, address-family, and SCS1-dependent fields are
    /// intentionally absent: they require separate authority-bearing seams.
    ///
    /// # Errors
    /// Rejects a missing, extra, reordered, or substituted property before a
    /// later execution or release transition can use this requested state.
    pub fn verify_readback(
        readback: &[SystemdHardeningProperty],
    ) -> Result<(), TransientUnitHardeningError> {
        if readback == Self::requested_properties() {
            Ok(())
        } else {
            Err(TransientUnitHardeningError::ReadbackMismatch)
        }
    }
}
