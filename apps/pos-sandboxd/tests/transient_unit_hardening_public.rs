use std::error::Error;

use pos_sandboxd::{
    SystemdHardeningProperty, SystemdHardeningValue, TransientUnitHardening,
    TransientUnitHardeningError,
};
use zvariant::{serialized::Context, to_bytes, Value, LE};

#[test]
fn static_hardening_bundle_has_exact_names_values_signatures_and_dbus_roundtrips(
) -> Result<(), Box<dyn Error>> {
    let properties = TransientUnitHardening::requested_properties();
    let expected = [
        ("Type", "s", SystemdHardeningValue::String("exec")),
        ("DynamicUser", "b", SystemdHardeningValue::Bool(true)),
        ("NoNewPrivileges", "b", SystemdHardeningValue::Bool(true)),
        ("PrivateDevices", "b", SystemdHardeningValue::Bool(true)),
        ("PrivateIPC", "b", SystemdHardeningValue::Bool(true)),
        ("PrivateMounts", "b", SystemdHardeningValue::Bool(true)),
        ("PrivateNetwork", "b", SystemdHardeningValue::Bool(true)),
        ("PrivatePIDs", "s", SystemdHardeningValue::String("yes")),
        ("PrivateUsersEx", "s", SystemdHardeningValue::String("self")),
        ("CapabilityBoundingSet", "t", SystemdHardeningValue::U64(0)),
        ("AmbientCapabilities", "t", SystemdHardeningValue::U64(0)),
        (
            "ProtectSystem",
            "s",
            SystemdHardeningValue::String("strict"),
        ),
        ("ProtectHome", "s", SystemdHardeningValue::String("yes")),
        (
            "ProtectControlGroupsEx",
            "s",
            SystemdHardeningValue::String("strict"),
        ),
        (
            "ProtectKernelTunables",
            "b",
            SystemdHardeningValue::Bool(true),
        ),
        (
            "ProtectKernelModules",
            "b",
            SystemdHardeningValue::Bool(true),
        ),
        ("ProtectKernelLogs", "b", SystemdHardeningValue::Bool(true)),
        ("ProtectClock", "b", SystemdHardeningValue::Bool(true)),
        ("ProtectHostname", "b", SystemdHardeningValue::Bool(true)),
        (
            "ProtectProc",
            "s",
            SystemdHardeningValue::String("invisible"),
        ),
        ("ProcSubset", "s", SystemdHardeningValue::String("pid")),
        (
            "RestrictNamespaces",
            "t",
            SystemdHardeningValue::U64(0x7e02_0080),
        ),
        ("RestrictSUIDSGID", "b", SystemdHardeningValue::Bool(true)),
        ("RestrictRealtime", "b", SystemdHardeningValue::Bool(true)),
        ("LockPersonality", "b", SystemdHardeningValue::Bool(true)),
        (
            "SystemCallArchitectures",
            "as",
            SystemdHardeningValue::StringArray(&["native"]),
        ),
        ("UMask", "u", SystemdHardeningValue::U32(0o077)),
        (
            "KillMode",
            "s",
            SystemdHardeningValue::String("control-group"),
        ),
        ("SendSIGKILL", "b", SystemdHardeningValue::Bool(true)),
    ];
    assert_eq!(properties.len(), expected.len());

    for (property, (name, signature, value)) in properties.iter().zip(expected) {
        assert_eq!(property.name(), name);
        assert_eq!(property.value(), value);
        assert_eq!(property.value().dbus_signature(), signature);
        match property.value() {
            SystemdHardeningValue::Bool(value) => {
                assert_eq!(Value::from(value).value_signature().to_string(), "b");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (bool, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::String(value) => {
                assert_eq!(Value::from(value).value_signature().to_string(), "s");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (String, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::U64(value) => {
                assert_eq!(Value::from(value).value_signature().to_string(), "t");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (u64, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::U32(value) => {
                assert_eq!(Value::from(value).value_signature().to_string(), "u");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (u32, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::StringArray(value) => {
                let value = value.iter().map(ToString::to_string).collect::<Vec<_>>();
                assert_eq!(
                    Value::from(value.clone()).value_signature().to_string(),
                    "as"
                );
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (Vec<String>, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
        }
    }
    Ok(())
}

#[test]
fn only_the_complete_ordered_static_bundle_is_accepted() {
    let expected = TransientUnitHardening::requested_properties();
    assert_eq!(TransientUnitHardening::verify_readback(expected), Ok(()));

    let mut missing = expected.to_vec();
    missing.pop();
    let mut extra = expected.to_vec();
    extra.push(SystemdHardeningProperty::TypeExec);
    let mut reordered = expected.to_vec();
    reordered.swap(0, 1);
    let mut substituted = expected.to_vec();
    substituted[0] = SystemdHardeningProperty::PrivateNetwork;

    for readback in [missing, extra, reordered, substituted] {
        assert_eq!(
            TransientUnitHardening::verify_readback(&readback),
            Err(TransientUnitHardeningError::ReadbackMismatch)
        );
    }
}

#[test]
fn public_type_cannot_represent_dynamic_or_untyped_properties() {
    let names = TransientUnitHardening::requested_properties()
        .iter()
        .map(|property| property.name())
        .collect::<Vec<_>>();
    for omitted in [
        "RootDirectory",
        "BindReadOnlyPaths",
        "RootImage",
        "RootHash",
        "RootHashSignature",
        "RootImagePolicy",
        "SystemCallFilter",
        "RestrictAddressFamilies",
        "ExtraFileDescriptors",
    ] {
        assert!(!names.contains(&omitted));
    }
}

#[test]
fn public_error_has_a_closed_diagnostic_message() {
    assert_eq!(
        TransientUnitHardeningError::ReadbackMismatch.to_string(),
        "systemd transient-unit hardening readback differs from the prescribed bundle"
    );
}
