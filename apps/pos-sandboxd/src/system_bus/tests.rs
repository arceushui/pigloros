use std::{
    error::Error,
    fs::File,
    os::fd::OwnedFd as StdOwnedFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use zbus::{
    connection::{socket::channel::Channel, Builder},
    fdo,
    object_server::SignalEmitter,
    zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Structure},
    Guid,
};

use super::*;
use crate::{
    ActivatedRootDirectory, LaunchMode, LauncherSource, SystemCallFilter, TransientUnitLaunchInputs,
};

const X86_64: &[u8] = include_bytes!(
    "../../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const JOB_PATH: &str = "/org/freedesktop/systemd1/job/381";
const UNRELATED_JOB_PATH: &str = "/org/freedesktop/systemd1/job/999";
const UNIT_PATH: &str = "/org/freedesktop/systemd1/unit/pigloros_2dattempt_2dtest_2eservice";
const ROOT_DIRECTORY: &str = "/run/pigloros/attempt-381/root";
const ROOT_IMAGE_POLICY: &str = "root=verity+signed";
const EXPECTED_PROPERTY_SHAPE: [(&str, &str); 35] = [
    ("Type", "s"),
    ("RootDirectory", "s"),
    ("BindReadOnlyPaths", "a(ssbt)"),
    ("DynamicUser", "b"),
    ("NoNewPrivileges", "b"),
    ("PrivateDevices", "b"),
    ("PrivateIPC", "b"),
    ("PrivateMounts", "b"),
    ("PrivateNetwork", "b"),
    ("PrivatePIDs", "s"),
    ("PrivateUsersEx", "s"),
    ("CapabilityBoundingSet", "t"),
    ("AmbientCapabilities", "t"),
    ("ProtectSystem", "s"),
    ("ProtectHome", "s"),
    ("ProtectControlGroupsEx", "s"),
    ("ProtectKernelTunables", "b"),
    ("ProtectKernelModules", "b"),
    ("ProtectKernelLogs", "b"),
    ("ProtectClock", "b"),
    ("ProtectHostname", "b"),
    ("ProtectProc", "s"),
    ("ProcSubset", "s"),
    ("RestrictNamespaces", "t"),
    ("RestrictSUIDSGID", "b"),
    ("RestrictRealtime", "b"),
    ("LockPersonality", "b"),
    ("SystemCallArchitectures", "as"),
    ("SystemCallFilter", "(bas)"),
    ("RestrictAddressFamilies", "(bas)"),
    ("UMask", "u"),
    ("KillMode", "s"),
    ("SendSIGKILL", "b"),
    ("FileDescriptorStoreMax", "u"),
    ("ExtraFileDescriptors", "a(hs)"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedStart {
    unit_name: String,
    mode: String,
    property_names: Vec<String>,
    property_signatures: Vec<String>,
    descriptor_names: Vec<String>,
    auxiliary_count: usize,
}

struct RecordingManager {
    observed: Arc<Mutex<Option<ObservedStart>>>,
    subscribed: Arc<AtomicBool>,
    behavior: ManagerBehavior,
}

#[derive(Clone)]
struct ManagerBehavior {
    reject: bool,
    result: String,
    emit_unrelated: bool,
    completion_unit: Option<String>,
    emit_completion: bool,
}

impl Default for ManagerBehavior {
    fn default() -> Self {
        Self {
            reject: false,
            result: "done".to_owned(),
            emit_unrelated: false,
            completion_unit: None,
            emit_completion: true,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl RecordingManager {
    #[zbus(name = "Subscribe")]
    fn subscribe(&self) {
        self.subscribed.store(true, Ordering::SeqCst);
    }

    #[zbus(name = "StartTransientUnit")]
    async fn start_transient_unit(
        &self,
        name: String,
        mode: String,
        properties: Vec<(String, OwnedValue)>,
        auxiliary: Vec<(String, Vec<(String, OwnedValue)>)>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<OwnedObjectPath> {
        if !self.subscribed.load(Ordering::SeqCst) {
            return Err(fdo::Error::Failed(
                "StartTransientUnit arrived before Subscribe".to_owned(),
            ));
        }
        if self.behavior.reject {
            return Err(fdo::Error::AccessDenied("test rejection".to_owned()));
        }
        let property_names = properties
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let property_signatures = properties
            .iter()
            .map(|(_, value)| value.value_signature().to_string())
            .collect::<Vec<_>>();
        let descriptor_names = properties
            .into_iter()
            .find_map(|(property, value)| {
                (property == "ExtraFileDescriptors").then(|| descriptor_names(value))
            })
            .transpose()?
            .ok_or_else(|| fdo::Error::Failed("missing descriptor property".to_owned()))?;
        let auxiliary_count = auxiliary.len();
        // The generated D-Bus interface owns every decoded wire argument.
        drop(auxiliary);
        let call = ObservedStart {
            unit_name: name,
            mode,
            property_names,
            property_signatures,
            descriptor_names,
            auxiliary_count,
        };
        self.observed
            .lock()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?
            .replace(call);
        let job_path = OwnedObjectPath::try_from(JOB_PATH)
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        if self.behavior.emit_unrelated {
            let unrelated = OwnedObjectPath::try_from(UNRELATED_JOB_PATH)
                .map_err(|error| fdo::Error::Failed(error.to_string()))?;
            Self::job_removed(
                &emitter,
                999,
                unrelated,
                "unrelated.service".to_owned(),
                "failed".to_owned(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        if self.behavior.emit_completion {
            Self::job_removed(
                &emitter,
                381,
                job_path.clone(),
                self.behavior
                    .completion_unit
                    .clone()
                    .unwrap_or_else(|| name.clone()),
                self.behavior.result.clone(),
            )
            .await
            .map_err(|error| fdo::Error::Failed(error.to_string()))?;
        }
        Ok(job_path)
    }

    #[zbus(name = "GetUnit")]
    fn get_unit(&self, _name: String) -> fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from(UNIT_PATH).map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    #[zbus(signal, name = "JobRemoved")]
    async fn job_removed(
        emitter: &SignalEmitter<'_>,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;
}

struct RecordingService {
    system_call_filter: Vec<String>,
    root_directory: String,
    fail_root_directory: bool,
}

impl RecordingService {
    fn exact(system_call_filter: Vec<String>) -> Self {
        Self {
            system_call_filter,
            root_directory: ROOT_DIRECTORY.to_owned(),
            fail_root_directory: false,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.systemd1.Service")]
impl RecordingService {
    #[zbus(property, name = "Type")]
    fn type_property(&self) -> &str {
        "exec"
    }

    #[zbus(property, name = "RootDirectory")]
    fn root_directory(&self) -> fdo::Result<&str> {
        if self.fail_root_directory {
            Err(fdo::Error::Failed("test readback failure".to_owned()))
        } else {
            Ok(&self.root_directory)
        }
    }

    #[zbus(property, name = "BindReadOnlyPaths")]
    fn bind_read_only_paths(&self) -> Vec<(String, String, bool, u64)> {
        vec![(
            "/usr/lib/pigloros/release-launcher".to_owned(),
            "/.pigloros/release-launcher".to_owned(),
            false,
            0,
        )]
    }

    #[zbus(property, name = "DynamicUser")]
    const fn dynamic_user(&self) -> bool {
        true
    }

    #[zbus(property, name = "NoNewPrivileges")]
    const fn no_new_privileges(&self) -> bool {
        true
    }

    #[zbus(property, name = "PrivateDevices")]
    const fn private_devices(&self) -> bool {
        true
    }

    #[zbus(property, name = "PrivateIPC")]
    const fn private_ipc(&self) -> bool {
        true
    }

    #[zbus(property, name = "PrivateMounts")]
    const fn private_mounts(&self) -> bool {
        true
    }

    #[zbus(property, name = "PrivateNetwork")]
    const fn private_network(&self) -> bool {
        true
    }

    #[zbus(property, name = "PrivatePIDs")]
    fn private_pi_ds(&self) -> &str {
        "yes"
    }

    #[zbus(property, name = "PrivateUsersEx")]
    fn private_users_ex(&self) -> &str {
        "self"
    }

    #[zbus(property, name = "CapabilityBoundingSet")]
    const fn capability_bounding_set(&self) -> u64 {
        0
    }

    #[zbus(property, name = "AmbientCapabilities")]
    const fn ambient_capabilities(&self) -> u64 {
        0
    }

    #[zbus(property, name = "ProtectSystem")]
    fn protect_system(&self) -> &str {
        "strict"
    }

    #[zbus(property, name = "ProtectHome")]
    fn protect_home(&self) -> &str {
        "yes"
    }

    #[zbus(property, name = "ProtectControlGroupsEx")]
    fn protect_control_groups_ex(&self) -> &str {
        "strict"
    }

    #[zbus(property, name = "ProtectKernelTunables")]
    const fn protect_kernel_tunables(&self) -> bool {
        true
    }

    #[zbus(property, name = "ProtectKernelModules")]
    const fn protect_kernel_modules(&self) -> bool {
        true
    }

    #[zbus(property, name = "ProtectKernelLogs")]
    const fn protect_kernel_logs(&self) -> bool {
        true
    }

    #[zbus(property, name = "ProtectClock")]
    const fn protect_clock(&self) -> bool {
        true
    }

    #[zbus(property, name = "ProtectHostname")]
    const fn protect_hostname(&self) -> bool {
        true
    }

    #[zbus(property, name = "ProtectProc")]
    fn protect_proc(&self) -> &str {
        "invisible"
    }

    #[zbus(property, name = "ProcSubset")]
    fn proc_subset(&self) -> &str {
        "pid"
    }

    #[zbus(property, name = "RestrictNamespaces")]
    const fn restrict_namespaces(&self) -> u64 {
        0x7e02_0080
    }

    #[zbus(property, name = "RestrictSUIDSGID")]
    const fn restrict_suidsgid(&self) -> bool {
        true
    }

    #[zbus(property, name = "RestrictRealtime")]
    const fn restrict_realtime(&self) -> bool {
        true
    }

    #[zbus(property, name = "LockPersonality")]
    const fn lock_personality(&self) -> bool {
        true
    }

    #[zbus(property, name = "SystemCallArchitectures")]
    fn system_call_architectures(&self) -> Vec<String> {
        vec!["native".to_owned()]
    }

    #[zbus(property, name = "SystemCallFilter")]
    fn system_call_filter(&self) -> (bool, Vec<String>) {
        (true, self.system_call_filter.clone())
    }

    #[zbus(property, name = "RestrictAddressFamilies")]
    fn restrict_address_families(&self) -> (bool, Vec<String>) {
        (true, vec!["AF_UNIX".to_owned()])
    }

    #[zbus(property, name = "UMask")]
    const fn u_mask(&self) -> u32 {
        0o077
    }

    #[zbus(property, name = "KillMode")]
    fn kill_mode(&self) -> &str {
        "control-group"
    }

    #[zbus(property, name = "SendSIGKILL")]
    const fn send_sigkill(&self) -> bool {
        true
    }

    #[zbus(property, name = "FileDescriptorStoreMax")]
    const fn file_descriptor_store_max(&self) -> u32 {
        0
    }

    #[zbus(property, name = "ExtraFileDescriptorNames")]
    fn extra_file_descriptor_names(&self) -> Vec<String> {
        vec![
            "piglor-host-service-v1".to_owned(),
            "piglor-release-v1".to_owned(),
        ]
    }

    #[zbus(property, name = "RootImagePolicy")]
    fn root_image_policy(&self) -> &str {
        ROOT_IMAGE_POLICY
    }
}

fn descriptor_names(value: OwnedValue) -> fdo::Result<Vec<String>> {
    Vec::<Structure<'static>>::try_from(value)
        .map_err(|error| fdo::Error::Failed(error.to_string()))?
        .into_iter()
        .map(|descriptor| {
            let mut fields = descriptor.into_fields().into_iter();
            fields
                .next()
                .ok_or_else(|| fdo::Error::Failed("descriptor is missing its fd".to_owned()))?;
            let name = fields
                .next()
                .ok_or_else(|| fdo::Error::Failed("descriptor is missing its name".to_owned()))?;
            String::try_from(name).map_err(|error| fdo::Error::Failed(error.to_string()))
        })
        .collect()
}

#[tokio::test]
async fn generated_proxy_submits_the_exact_closed_request() -> Result<(), Box<dyn Error>> {
    let observed = Arc::new(Mutex::new(None));
    let mut behavior = ManagerBehavior::default();
    behavior.emit_unrelated = true;
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::clone(&observed), behavior, service).await?;
    let name = TransientServiceUnitName::from_attempt_id([0xab; 16])?;
    assert_eq!(
        name.as_str(),
        "pigloros-attempt-abababababababababababababababab.service"
    );

    let verified = transport
        .start(
            name.clone(),
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await?;
    assert_eq!(verified.unit_name(), &name);
    assert_eq!(verified.job().as_str(), JOB_PATH);
    assert_eq!(verified.unit_path(), UNIT_PATH);
    assert_eq!(verified.requested_readback().len(), 35);
    assert_eq!(verified.requested_readback()[0].name(), "Type");
    assert_eq!(
        verified.requested_readback()[34].name(),
        "ExtraFileDescriptors"
    );
    assert_eq!(
        verified.manager_readback().property(),
        SystemdManagerReadbackOnlyProperty::RootImagePolicy
    );
    assert_eq!(verified.manager_readback().value(), ROOT_IMAGE_POLICY);

    let call = observed
        .lock()
        .map_err(|error| error.to_string())?
        .clone()
        .ok_or("manager did not observe StartTransientUnit")?;
    assert_eq!(
        call.unit_name,
        "pigloros-attempt-abababababababababababababababab.service"
    );
    assert_eq!(call.mode, "fail");
    let property_shape = call
        .property_names
        .iter()
        .zip(&call.property_signatures)
        .map(|(name, signature)| (name.as_str(), signature.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(property_shape, EXPECTED_PROPERTY_SHAPE);
    assert_eq!(
        call.descriptor_names,
        ["piglor-host-service-v1", "piglor-release-v1"]
    );
    assert_eq!(call.auxiliary_count, 0);
    Ok(())
}

#[tokio::test]
async fn generated_proxy_preserves_manager_rejection() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        reject: true,
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let result = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x01; 16])?,
            request(LaunchMode::AirGapped)?,
        )
        .await;
    let error = result.err().ok_or("manager rejection was accepted")?;
    assert!(error.to_string().contains("systemd rejected"));
    let SystemdTransientUnitTransportError::ManagerCall(_) = error else {
        return Err("manager rejection had the wrong error class".into());
    };
    Ok(())
}

#[tokio::test]
async fn every_non_successful_job_result_fails_closed() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("canceled", SystemdJobFailure::Canceled),
        ("timeout", SystemdJobFailure::Timeout),
        ("failed", SystemdJobFailure::Failed),
        ("dependency", SystemdJobFailure::Dependency),
        ("skipped", SystemdJobFailure::Skipped),
        (
            "future-result",
            SystemdJobFailure::Unknown("future-result".to_owned()),
        ),
    ];
    for (result, expected) in cases {
        let behavior = ManagerBehavior {
            result: result.to_owned(),
            ..ManagerBehavior::default()
        };
        let service = RecordingService::exact(expected_system_call_filter()?);
        let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
        let error = transport
            .start(
                TransientServiceUnitName::from_attempt_id([0x02; 16])?,
                request(LaunchMode::AirGapped)?,
            )
            .await
            .err()
            .ok_or("failed job result was accepted")?;
        let SystemdTransientUnitTransportError::JobFailed(actual) = error else {
            return Err("failed job result had the wrong error class".into());
        };
        assert_eq!(actual, expected);
    }
    Ok(())
}

#[tokio::test]
async fn matching_job_path_cannot_substitute_the_unit_name() -> Result<(), Box<dyn Error>> {
    let behavior = ManagerBehavior {
        completion_unit: Some("substituted.service".to_owned()),
        ..ManagerBehavior::default()
    };
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), behavior, service).await?;
    let expected = TransientServiceUnitName::from_attempt_id([0x03; 16])?;
    let error = transport
        .start(expected.clone(), request(LaunchMode::AirGapped)?)
        .await
        .err()
        .ok_or("substituted completion unit was accepted")?;
    let SystemdTransientUnitTransportError::JobIdentityMismatch {
        expected: observed_expected,
        actual,
    } = error
    else {
        return Err("substituted completion unit had the wrong error class".into());
    };
    assert_eq!(observed_expected, expected.as_str());
    assert_eq!(actual, "substituted.service");
    Ok(())
}

#[tokio::test]
async fn unequal_typed_property_readback_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.root_directory = "/run/pigloros/substituted/root".to_owned();
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x04; 16])?,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await
        .err()
        .ok_or("unequal property readback was accepted")?;
    assert!(matches!(
        error,
        SystemdTransientUnitTransportError::Readback(TransientUnitRequestError::ReadbackMismatch)
    ));
    Ok(())
}

#[tokio::test]
async fn typed_property_read_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let mut service = RecordingService::exact(expected_system_call_filter()?);
    service.fail_root_directory = true;
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let error = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x05; 16])?,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await
        .err()
        .ok_or("failed property read was accepted")?;
    let SystemdTransientUnitTransportError::PropertyReadback { property, .. } = error else {
        return Err("failed property read had the wrong error class".into());
    };
    assert_eq!(property, "RootDirectory");
    Ok(())
}

async fn transport(
    observed: Arc<Mutex<Option<ObservedStart>>>,
    behavior: ManagerBehavior,
    service: RecordingService,
) -> Result<(SystemdTransientUnitTransport, zbus::Connection), Box<dyn Error>> {
    let guid = Guid::generate();
    let (server_socket, client_socket) = Channel::pair();
    let subscribed = Arc::new(AtomicBool::new(false));
    let server = Builder::authenticated_socket(server_socket, guid.clone())?
        .p2p()
        .serve_at(
            MANAGER_PATH,
            RecordingManager {
                observed,
                subscribed,
                behavior,
            },
        )?
        .serve_at(UNIT_PATH, service)?
        .build();
    let client = Builder::authenticated_socket(client_socket, guid)?
        .p2p()
        .build();
    let (server, client) = tokio::join!(server, client);
    let server = server?;
    let client = client?;
    Ok((
        SystemdTransientUnitTransport::from_connection(client).await?,
        server,
    ))
}

fn expected_system_call_filter() -> Result<Vec<String>, Box<dyn Error>> {
    SandboxSyscallSetV1::from_canonical_cbor(X86_64)
        .map(|authority| authority.expected_effective_names)
        .map_err(Into::into)
}

fn request(mode: LaunchMode) -> Result<TransientUnitRequest, Box<dyn Error>> {
    let authority = SandboxSyscallSetV1::from_canonical_cbor(X86_64)?;
    let filter = SystemCallFilter::from_selected_record(
        X86_64,
        authority.syscall_set_digest,
        SandboxArchitecture::X86_64,
    )?;
    let inputs = TransientUnitLaunchInputs::new(
        ActivatedRootDirectory::new("/run/pigloros/attempt-381/root")?,
        LauncherSource::new("/usr/lib/pigloros/release-launcher")?,
        mode,
        descriptor()?,
    );
    Ok(TransientUnitRequest::compile(inputs, filter))
}

fn descriptor() -> Result<OwnedFd, std::io::Error> {
    File::open("/dev/null").map(|file| OwnedFd::from(StdOwnedFd::from(file)))
}

fn value() -> SystemdTransientUnitValue {
    SystemdTransientUnitValue::FileDescriptorStoreMax(1)
}

#[test]
fn owned_value_failure_is_classified() {
    let error = encode_property_with("TestProperty", value(), |_| {
        Err(zvariant::Error::IncorrectType)
    });
    assert_eq!(
        error.as_ref().err().map(ToString::to_string),
        Some("failed to serialize the typed transient-unit request".to_owned())
    );
}

#[test]
fn call_serialization_failure_is_classified() {
    let error = classify_call_error(zbus::Error::Variant(zvariant::Error::IncorrectType));
    assert_eq!(
        error.to_string(),
        "failed to serialize the typed transient-unit request"
    );
}

#[tokio::test]
async fn manager_proxy_failure_is_classified() -> Result<(), Box<dyn Error>> {
    let service = RecordingService::exact(expected_system_call_filter()?);
    let (transport, _server) = transport(
        Arc::new(Mutex::new(None)),
        ManagerBehavior::default(),
        service,
    )
    .await?;
    let proxy_error = zbus::Error::Failure("test proxy failure".to_owned());
    let name = TransientServiceUnitName("test.service".to_owned());
    let request = request(LaunchMode::AirGapped)?;
    let error = submit_and_verify(
        Err(proxy_error),
        Vec::new(),
        name,
        &request,
        &transport.connection,
    )
    .await;
    assert_eq!(
        error.as_ref().err().map(ToString::to_string),
        Some("failed to construct the typed systemd manager proxy".to_owned())
    );
    Ok(())
}
