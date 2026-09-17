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
    assert_eq!(properties.len(), 29);
    assert_eq!(properties[0], SystemdHardeningProperty::TypeExec);
    assert_eq!(properties[28], SystemdHardeningProperty::SendSigKill);

    for property in properties {
        match property.value() {
            SystemdHardeningValue::Bool(value) => {
                assert_eq!(property.value().dbus_signature(), "b");
                assert_eq!(Value::from(value).value_signature().to_string(), "b");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (bool, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::String(value) => {
                assert_eq!(property.value().dbus_signature(), "s");
                assert_eq!(Value::from(value).value_signature().to_string(), "s");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (String, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::U64(value) => {
                assert_eq!(property.value().dbus_signature(), "t");
                assert_eq!(Value::from(value).value_signature().to_string(), "t");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (u64, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::U32(value) => {
                assert_eq!(property.value().dbus_signature(), "u");
                assert_eq!(Value::from(value).value_signature().to_string(), "u");
                let encoded = to_bytes(Context::new_dbus(LE, 0), &value)?;
                let (decoded, consumed): (u32, usize) = encoded.deserialize()?;
                assert_eq!(decoded, value);
                assert_eq!(consumed, encoded.len());
            }
            SystemdHardeningValue::StringArray(value) => {
                assert_eq!(property.value().dbus_signature(), "as");
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
