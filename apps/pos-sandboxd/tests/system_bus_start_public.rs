use std::{
    error::Error,
    fs::File,
    os::fd::OwnedFd as StdOwnedFd,
    sync::{Arc, Mutex},
};

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::SandboxArchitecture;
use pos_sandboxd::{
    ActivatedRootDirectory, LaunchMode, LauncherSource, SystemCallFilter,
    SystemdTransientUnitTransport, SystemdTransientUnitTransportError, TransientServiceUnitName,
    TransientUnitLaunchInputs, TransientUnitRequest,
};
use zbus::{
    connection::{socket::channel::Channel, Builder},
    fdo,
    zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Structure},
    Guid,
};

const X86_64: &[u8] = include_bytes!(
    "../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const JOB_PATH: &str = "/org/freedesktop/systemd1/job/381";

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
    reject: bool,
}

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl RecordingManager {
    #[zbus(name = "StartTransientUnit")]
    // The generated D-Bus interface requires its decoded wire arguments by value.
    #[allow(clippy::needless_pass_by_value)]
    fn start_transient_unit(
        &self,
        name: String,
        mode: String,
        properties: Vec<(String, OwnedValue)>,
        auxiliary: Vec<(String, Vec<(String, OwnedValue)>)>,
    ) -> fdo::Result<OwnedObjectPath> {
        if self.reject {
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
        let call = ObservedStart {
            unit_name: name,
            mode,
            property_names,
            property_signatures,
            descriptor_names,
            auxiliary_count: auxiliary.len(),
        };
        self.observed
            .lock()
            .map_err(|error| fdo::Error::Failed(error.to_string()))?
            .replace(call);
        OwnedObjectPath::try_from(JOB_PATH).map_err(|error| fdo::Error::Failed(error.to_string()))
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
    let (transport, _server) = transport(Arc::clone(&observed), false).await?;
    let name = TransientServiceUnitName::from_attempt_id([0xab; 16]);
    assert_eq!(
        name.as_str(),
        "pigloros-attempt-abababababababababababababababab.service"
    );

    let job = transport
        .start(
            name,
            request(LaunchMode::Local {
                host_service: descriptor()?,
            })?,
        )
        .await?;
    assert_eq!(job.as_str(), JOB_PATH);

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
    assert_eq!(call.property_names.len(), 35);
    assert_eq!(call.property_names[0], "Type");
    assert_eq!(call.property_names[1], "RootDirectory");
    assert_eq!(call.property_names[34], "ExtraFileDescriptors");
    assert_eq!(call.property_signatures[0], "s");
    assert_eq!(call.property_signatures[2], "a(ssbt)");
    assert_eq!(call.property_signatures[28], "(bas)");
    assert_eq!(call.property_signatures[34], "a(hs)");
    assert_eq!(
        call.descriptor_names,
        ["piglor-host-service-v1", "piglor-release-v1"]
    );
    assert_eq!(call.auxiliary_count, 0);
    Ok(())
}

#[tokio::test]
async fn generated_proxy_preserves_manager_rejection() -> Result<(), Box<dyn Error>> {
    let (transport, _server) = transport(Arc::new(Mutex::new(None)), true).await?;
    let result = transport
        .start(
            TransientServiceUnitName::from_attempt_id([0x01; 16]),
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

async fn transport(
    observed: Arc<Mutex<Option<ObservedStart>>>,
    reject: bool,
) -> Result<(SystemdTransientUnitTransport, zbus::Connection), Box<dyn Error>> {
    let guid = Guid::generate();
    let (server_socket, client_socket) = Channel::pair();
    let server = Builder::authenticated_socket(server_socket, guid.clone())?
        .p2p()
        .serve_at(MANAGER_PATH, RecordingManager { observed, reject })?
        .build();
    let client = Builder::authenticated_socket(client_socket, guid)?
        .p2p()
        .build();
    let (server, client) = tokio::join!(server, client);
    let server = server?;
    let client = client?;
    Ok((
        SystemdTransientUnitTransport::from_connection(client),
        server,
    ))
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
