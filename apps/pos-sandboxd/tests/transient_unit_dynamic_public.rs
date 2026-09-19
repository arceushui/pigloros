use std::{error::Error, fs::File, os::fd::OwnedFd as StdOwnedFd};

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use pos_sandboxd::{
    ActivatedRootDirectory, LaunchMode, LauncherSource, SystemCallFilter, SystemdManagerReadback,
    SystemdManagerReadbackOnlyProperty, SystemdTransientUnitReadback,
    SystemdTransientUnitReadbackValue, SystemdTransientUnitValue, TransientUnitLaunchInputs,
    TransientUnitRequest, TransientUnitRequestError,
};
use zvariant::{serialized::Context, to_bytes, OwnedFd, Type, LE};

const X86_64: &[u8] = include_bytes!(
    "../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);

const EXPECTED_PROPERTY_NAMES: [&str; 34] = [
    "Type",
    "RootDirectory",
    "BindReadOnlyPaths",
    "DynamicUser",
    "NoNewPrivileges",
    "PrivateDevices",
    "PrivateIPC",
    "PrivateMounts",
    "PrivateNetwork",
    "PrivatePIDs",
    "PrivateUsersEx",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "ProtectSystem",
    "ProtectHome",
    "ProtectControlGroupsEx",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectClock",
    "ProtectHostname",
    "ProtectProc",
    "ProcSubset",
    "RestrictNamespaces",
    "RestrictSUIDSGID",
    "RestrictRealtime",
    "LockPersonality",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "RestrictAddressFamilies",
    "UMask",
    "KillMode",
    "SendSIGKILL",
    "ExtraFileDescriptors",
];

#[test]
fn local_request_has_the_exact_ordered_dynamic_properties_and_dbus_signatures(
) -> Result<(), Box<dyn Error>> {
    let request = request(LaunchMode::Local {
        host_service: descriptor()?,
    })?;
    let properties = request.requested_properties();
    assert_eq!(
        properties
            .iter()
            .map(pos_sandboxd::SystemdTransientUnitProperty::name)
            .collect::<Vec<_>>(),
        EXPECTED_PROPERTY_NAMES
    );
    assert_eq!(properties[1].value().dbus_signature(), "s");
    assert_eq!(properties[0].value().dbus_signature(), "s");
    assert_eq!(properties[2].value().dbus_signature(), "a(ssbt)");
    assert_eq!(properties[28].value().dbus_signature(), "(bas)");
    assert_eq!(properties[29].value().dbus_signature(), "(bas)");
    assert_eq!(properties[33].value().dbus_signature(), "a(hs)");

    match properties[1].value() {
        SystemdTransientUnitValue::RootDirectory(value) => {
            let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
            let (decoded, consumed): (String, usize) = encoded.deserialize()?;
            assert_eq!(decoded, *value);
            assert_eq!(consumed, encoded.len());
            assert_eq!(value, "/run/pigloros/attempt-42/root");
        }
        _value => return Err("RootDirectory must have a string value".into()),
    }
    match properties[2].value() {
        SystemdTransientUnitValue::BindReadOnlyPaths(value) => {
            let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
            let (decoded, consumed): (Vec<(String, String, bool, u64)>, usize) =
                encoded.deserialize()?;
            assert_eq!(decoded, *value);
            assert_eq!(consumed, encoded.len());
            assert_eq!(
                value,
                &[(
                    "/usr/lib/pigloros/release-launcher".to_owned(),
                    "/.pigloros/release-launcher".to_owned(),
                    false,
                    0,
                )]
            );
        }
        _value => return Err("BindReadOnlyPaths must have an a(ssbt) value".into()),
    }
    match properties[29].value() {
        SystemdTransientUnitValue::RestrictAddressFamilies(value) => {
            let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
            let (decoded, consumed): ((bool, Vec<String>), usize) = encoded.deserialize()?;
            assert_eq!(decoded, *value);
            assert_eq!(consumed, encoded.len());
            assert_eq!(value, &(true, vec!["AF_UNIX".to_owned()]));
        }
        _value => return Err("RestrictAddressFamilies must have a (bas) value".into()),
    }
    match properties[28].value() {
        SystemdTransientUnitValue::SystemCallFilter(value) => {
            let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
            let (decoded, consumed): ((bool, Vec<String>), usize) = encoded.deserialize()?;
            assert_eq!(decoded, *value);
            assert_eq!(consumed, encoded.len());
        }
        _value => return Err("SystemCallFilter must have a (bas) value".into()),
    }
    match properties[33].value() {
        SystemdTransientUnitValue::ExtraFileDescriptors(value) => {
            assert_eq!(
                <Vec<(OwnedFd, String)> as Type>::SIGNATURE.to_string(),
                "a(hs)"
            );
            assert_eq!(value.len(), 2);
            assert_eq!(value[0].1, "piglor-host-service-v1");
            assert_eq!(value[1].1, "piglor-release-v1");
            let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
            let (decoded, consumed): (Vec<(OwnedFd, String)>, usize) = encoded.deserialize()?;
            assert_eq!(decoded.len(), 2);
            assert_eq!(decoded[0].1, "piglor-host-service-v1");
            assert_eq!(decoded[1].1, "piglor-release-v1");
            assert_eq!(consumed, encoded.len());
        }
        _value => return Err("ExtraFileDescriptors must have an a(hs) value".into()),
    }
    Ok(())
}

#[test]
fn non_local_modes_have_only_the_release_descriptor_and_no_network_families(
) -> Result<(), Box<dyn Error>> {
    for mode in [LaunchMode::AirGapped, LaunchMode::Replay, LaunchMode::Fork] {
        let request = request(mode)?;
        let properties = request.requested_properties();
        match properties[29].value() {
            SystemdTransientUnitValue::RestrictAddressFamilies(value) => {
                assert_eq!(value, &(true, Vec::new()));
                let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
                let (decoded, consumed): ((bool, Vec<String>), usize) = encoded.deserialize()?;
                assert_eq!(decoded, *value);
                assert_eq!(consumed, encoded.len());
            }
            _value => return Err("RestrictAddressFamilies must have a (bas) value".into()),
        }
        match properties[33].value() {
            SystemdTransientUnitValue::ExtraFileDescriptors(value) => {
                assert_eq!(value.len(), 1);
                assert_eq!(value[0].1, "piglor-release-v1");
                let encoded = to_bytes(Context::new_dbus(LE, 0), value)?;
                let (decoded, consumed): (Vec<(OwnedFd, String)>, usize) = encoded.deserialize()?;
                assert_eq!(decoded.len(), 1);
                assert_eq!(decoded[0].1, "piglor-release-v1");
                assert_eq!(consumed, encoded.len());
            }
            _value => return Err("ExtraFileDescriptors must have an a(hs) value".into()),
        }
    }
    Ok(())
}

#[test]
fn swapped_descriptor_name_and_fd_shape_is_rejected_before_transport() -> Result<(), Box<dyn Error>>
{
    let swapped = vec![("piglor-release-v1".to_owned(), descriptor()?)];
    assert_eq!(
        <Vec<(String, OwnedFd)> as Type>::SIGNATURE.to_string(),
        "a(sh)"
    );
    assert_ne!(
        <Vec<(String, OwnedFd)> as Type>::SIGNATURE,
        <Vec<(OwnedFd, String)> as Type>::SIGNATURE
    );
    let encoded = to_bytes(Context::new_dbus(LE, 0), &swapped)?;
    let rejected: zvariant::Result<(Vec<(OwnedFd, String)>, usize)> = encoded.deserialize();
    assert!(rejected.is_err());
    Ok(())
}

#[test]
fn only_normalized_bounded_provider_paths_can_compile() {
    for path in [
        "relative/root",
        "/",
        "/run",
        "/run//attempt/root",
        "/run/./attempt/root",
        "/run/attempt/../root",
        "/run/attempt/root/",
        "/run/attempt\0/root",
    ] {
        assert_eq!(
            ActivatedRootDirectory::new(path),
            Err(TransientUnitRequestError::InvalidRootDirectory)
        );
    }
    let oversized = format!("/run/{}", "a".repeat(4091));
    assert_eq!(
        ActivatedRootDirectory::new(oversized),
        Err(TransientUnitRequestError::InvalidRootDirectory)
    );
    for path in [
        "relative/launcher",
        "/usr//lib/launcher",
        "/usr/lib/../launcher",
    ] {
        assert_eq!(
            LauncherSource::new(path),
            Err(TransientUnitRequestError::InvalidLauncherSource)
        );
    }
    let oversized_launcher = format!("/{}", "a".repeat(4095));
    assert_eq!(
        LauncherSource::new(oversized_launcher),
        Err(TransientUnitRequestError::InvalidLauncherSource)
    );
}

#[test]
fn verifier_rejects_reordered_missing_extra_and_request_readback_substitutions(
) -> Result<(), Box<dyn Error>> {
    let authority = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    let request = request(LaunchMode::Local {
        host_service: descriptor()?,
    })?;
    let readback = exact_readback(&request, &authority.expected_effective_names);
    assert_eq!(request.verify_readback(&readback), Ok(()));

    let mut missing = readback.clone();
    missing.pop();
    let mut extra = readback.clone();
    extra.push(readback[0].clone());
    let mut reordered = readback.clone();
    reordered.swap(1, 2);
    let mut syscall_request_as_readback = readback;
    syscall_request_as_readback[28] = SystemdTransientUnitReadback::new(
        "SystemCallFilter",
        SystemdTransientUnitReadbackValue::BoolStringArray((true, authority.requested_names)),
    );
    let mut mistyped_root = exact_readback(&request, &authority.expected_effective_names);
    mistyped_root[1] = SystemdTransientUnitReadback::new(
        "RootDirectory",
        SystemdTransientUnitReadbackValue::BoolStringArray((true, Vec::new())),
    );
    let mut missing_descriptor = exact_readback(&request, &authority.expected_effective_names);
    missing_descriptor[33] = SystemdTransientUnitReadback::new(
        "ExtraFileDescriptors",
        SystemdTransientUnitReadbackValue::StringArray(Vec::new()),
    );
    let mut extra_descriptor = exact_readback(&request, &authority.expected_effective_names);
    extra_descriptor[33] = SystemdTransientUnitReadback::new(
        "ExtraFileDescriptors",
        SystemdTransientUnitReadbackValue::StringArray(vec![
            "piglor-host-service-v1".to_owned(),
            "piglor-release-v1".to_owned(),
            "unexpected".to_owned(),
        ]),
    );
    let mut reordered_descriptor = exact_readback(&request, &authority.expected_effective_names);
    reordered_descriptor[33] = SystemdTransientUnitReadback::new(
        "ExtraFileDescriptors",
        SystemdTransientUnitReadbackValue::StringArray(vec![
            "piglor-release-v1".to_owned(),
            "piglor-host-service-v1".to_owned(),
        ]),
    );
    for mutated in [
        missing,
        extra,
        reordered,
        syscall_request_as_readback,
        mistyped_root,
        missing_descriptor,
        extra_descriptor,
        reordered_descriptor,
    ] {
        assert_eq!(
            request.verify_readback(&mutated),
            Err(TransientUnitRequestError::ReadbackMismatch)
        );
    }
    Ok(())
}

#[test]
fn verifier_rejects_the_wrong_address_family_or_allow_list_mode() -> Result<(), Box<dyn Error>> {
    let authority = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    let request = request(LaunchMode::Local {
        host_service: descriptor()?,
    })?;
    for value in [
        (false, vec!["AF_UNIX".to_owned()]),
        (true, Vec::new()),
        (true, vec!["AF_INET".to_owned()]),
    ] {
        let mut readback = exact_readback(&request, &authority.expected_effective_names);
        readback[29] = SystemdTransientUnitReadback::new(
            "RestrictAddressFamilies",
            SystemdTransientUnitReadbackValue::BoolStringArray(value),
        );
        assert_eq!(
            request.verify_readback(&readback),
            Err(TransientUnitRequestError::ReadbackMismatch)
        );
    }
    Ok(())
}

#[test]
fn manager_only_root_image_policy_is_not_a_request_property() -> Result<(), Box<dyn Error>> {
    let request = request(LaunchMode::AirGapped)?;
    assert_eq!(
        SystemdManagerReadbackOnlyProperty::RootImagePolicy.name(),
        "RootImagePolicy"
    );
    assert_eq!(
        SystemdManagerReadbackOnlyProperty::RootImagePolicy.dbus_signature(),
        "s"
    );
    assert!(request
        .requested_properties()
        .iter()
        .all(|property| property.name() != "RootImagePolicy"));
    let readback = SystemdManagerReadback::new(
        SystemdManagerReadbackOnlyProperty::RootImagePolicy,
        "root=verity+signed",
    );
    assert_eq!(
        readback.property(),
        SystemdManagerReadbackOnlyProperty::RootImagePolicy
    );
    assert_eq!(readback.value(), "root=verity+signed");
    let root_image_policy = readback.value().to_owned();
    let encoded = to_bytes(Context::new_dbus(LE, 0), &root_image_policy)?;
    let (decoded, consumed): (String, usize) = encoded.deserialize()?;
    assert_eq!(decoded, readback.value());
    assert_eq!(consumed, encoded.len());
    Ok(())
}

fn request(mode: LaunchMode) -> Result<TransientUnitRequest, Box<dyn Error>> {
    let authority = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    let filter = SystemCallFilter::from_selected_record(
        X86_64,
        authority.syscall_set_digest,
        SandboxArchitecture::X86_64,
    )?;
    let inputs = TransientUnitLaunchInputs::new(
        ActivatedRootDirectory::new("/run/pigloros/attempt-42/root")?,
        LauncherSource::new("/usr/lib/pigloros/release-launcher")?,
        mode,
        descriptor()?,
    );
    Ok(TransientUnitRequest::compile(inputs, filter))
}

fn descriptor() -> Result<OwnedFd, std::io::Error> {
    File::open("/dev/null").map(|file| OwnedFd::from(StdOwnedFd::from(file)))
}

fn exact_readback(
    request: &TransientUnitRequest,
    expected_system_calls: &[String],
) -> Vec<SystemdTransientUnitReadback> {
    request
        .requested_properties()
        .iter()
        .map(|property| {
            let value = match property.value() {
                SystemdTransientUnitValue::Static(value) => {
                    SystemdTransientUnitReadbackValue::Static((*value).into())
                }
                SystemdTransientUnitValue::RootDirectory(value) => {
                    SystemdTransientUnitReadbackValue::String(value.clone())
                }
                SystemdTransientUnitValue::BindReadOnlyPaths(value) => {
                    SystemdTransientUnitReadbackValue::BindReadOnlyPaths(value.clone())
                }
                SystemdTransientUnitValue::SystemCallFilter(_) => {
                    SystemdTransientUnitReadbackValue::BoolStringArray((
                        true,
                        expected_system_calls.to_vec(),
                    ))
                }
                SystemdTransientUnitValue::RestrictAddressFamilies(value) => {
                    SystemdTransientUnitReadbackValue::BoolStringArray(value.clone())
                }
                SystemdTransientUnitValue::ExtraFileDescriptors(value) => {
                    SystemdTransientUnitReadbackValue::StringArray(
                        value.iter().map(|(_, name)| name.clone()).collect(),
                    )
                }
            };
            SystemdTransientUnitReadback::new(property.name(), value)
        })
        .collect()
}
