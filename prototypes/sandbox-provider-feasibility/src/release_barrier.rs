//! Hosted-only release-barrier proof for ADR-069 revision 19.

use crate::release_wire::{
    decode_launch_parameters, decode_release, encode_launch_parameters, encode_ready,
    fd_layout_digest, launch_parameter_digest, proof_digest, proof_signing_key, ready_digest,
    verify_release_signature, FdIdentity, FdLayout, LaunchParameters, Ready, Release,
};
use nix::{
    fcntl::{fcntl, AtFlags, FcntlArg, FdFlag},
    sys::{
        resource::{getrlimit, Resource, RLIM_INFINITY},
        socket::{
            getsockopt, recv, recvmsg, send, setsockopt, shutdown, socketpair, sockopt,
            AddressFamily, ControlMessageOwned, MsgFlags, Shutdown, SockFlag, SockType,
        },
        time::{TimeVal, TimeValLike as _},
    },
    time::{clock_gettime, ClockId},
    unistd::execveat,
};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{IoSliceMut, Read as _, Seek as _, SeekFrom, Write as _},
    os::{
        fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Component, Path},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use zbus::zvariant::{
    Array as ZbusArray, OwnedFd as ZbusOwnedFd, OwnedValue, StructureBuilder, Value as ZbusValue,
};

const RELEASE_LAUNCHER: &str = "/.pigloros/release-launcher";
const ADAPTER_PATH: &str = "/usr/bin/sandbox-provider-feasibility";
const RELEASE_NAME: &str = "piglor-release-v1";
const PROXY_NAME: &str = "piglor-host-service-v1";
const MAX_PACKET: usize = 64 * 1024;

struct DescriptorSet {
    descriptors: Vec<(String, OwnedFd)>,
    retained_peers: Vec<OwnedFd>,
}

struct ImageAuthority {
    root_image: String,
    root_hash: Vec<u8>,
    root_signature: Vec<u8>,
    sim1_digest: [u8; 32],
}

struct LaunchRecord {
    parameters: LaunchParameters,
    encoded: Vec<u8>,
    encoded_hex: String,
}

struct ProviderChannels {
    provider_proxy: Option<OwnedFd>,
    launcher_proxy: Option<OwnedFd>,
    provider_release: OwnedFd,
    launcher_release: OwnedFd,
}

struct LocalNetworkGuard {
    host_interface: Option<String>,
    expected_readback_digest: [u8; 32],
    observed_readback_digest: [u8; 32],
}

impl Drop for LocalNetworkGuard {
    fn drop(&mut self) {
        if let Some(host_interface) = &self.host_interface {
            let _ = Command::new("ip")
                .args(["link", "delete", "dev", host_interface])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionMode {
    Local,
    AirGapped,
    Replay,
    Fork,
}

impl ExecutionMode {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let value = arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("--mode="))
            .unwrap_or("local");
        match value {
            "local" => Ok(Self::Local),
            "air-gapped" => Ok(Self::AirGapped),
            "replay" => Ok(Self::Replay),
            "fork" => Ok(Self::Fork),
            _ => Err(format!("unknown execution mode {value}")),
        }
    }

    const fn ordinal(self) -> u8 {
        match self {
            Self::Local => 0,
            Self::AirGapped => 1,
            Self::Replay => 2,
            Self::Fork => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::AirGapped => "air-gapped",
            Self::Replay => "replay",
            Self::Fork => "fork",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofCase {
    Positive,
    MalformedRelease,
    DuplicateRelease,
    ReorderedRelease,
    ReleaseTimeout,
    MismatchedRelease,
    ReplayedRelease,
    ExpiredRelease,
    ReadbackMismatch,
    Cancellation,
    ProviderEof,
    ProviderDeathHold,
    MissingDescriptor,
    ExtraDescriptor,
    ReorderedDescriptors,
    WrongDescriptorName,
    WrongDescriptorType,
    HigherDescriptor,
}

impl ProofCase {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let Some(value) = arguments
            .iter()
            .find_map(|argument| argument.strip_prefix("--barrier-case="))
        else {
            return Ok(Self::Positive);
        };
        match value {
            "positive" => Ok(Self::Positive),
            "malformed-release" => Ok(Self::MalformedRelease),
            "duplicate-release" => Ok(Self::DuplicateRelease),
            "reordered-release" => Ok(Self::ReorderedRelease),
            "release-timeout" => Ok(Self::ReleaseTimeout),
            "mismatched-release" => Ok(Self::MismatchedRelease),
            "replayed-release" => Ok(Self::ReplayedRelease),
            "expired-release" => Ok(Self::ExpiredRelease),
            "readback-mismatch" => Ok(Self::ReadbackMismatch),
            "cancellation" => Ok(Self::Cancellation),
            "provider-eof" => Ok(Self::ProviderEof),
            "provider-death-hold" => Ok(Self::ProviderDeathHold),
            "missing-descriptor" => Ok(Self::MissingDescriptor),
            "extra-descriptor" => Ok(Self::ExtraDescriptor),
            "reordered-descriptors" => Ok(Self::ReorderedDescriptors),
            "wrong-descriptor-name" => Ok(Self::WrongDescriptorName),
            "wrong-descriptor-type" => Ok(Self::WrongDescriptorType),
            "higher-descriptor" => Ok(Self::HigherDescriptor),
            _ => Err(format!("unknown barrier case {value}")),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::MalformedRelease => "malformed-release",
            Self::DuplicateRelease => "duplicate-release",
            Self::ReorderedRelease => "reordered-release",
            Self::ReleaseTimeout => "release-timeout",
            Self::MismatchedRelease => "mismatched-release",
            Self::ReplayedRelease => "replayed-release",
            Self::ExpiredRelease => "expired-release",
            Self::ReadbackMismatch => "readback-mismatch",
            Self::Cancellation => "cancellation",
            Self::ProviderEof => "provider-eof",
            Self::ProviderDeathHold => "provider-death-hold",
            Self::MissingDescriptor => "missing-descriptor",
            Self::ExtraDescriptor => "extra-descriptor",
            Self::ReorderedDescriptors => "reordered-descriptors",
            Self::WrongDescriptorName => "wrong-descriptor-name",
            Self::WrongDescriptorType => "wrong-descriptor-type",
            Self::HigherDescriptor => "higher-descriptor",
        }
    }

    const fn is_descriptor_defect(self) -> bool {
        matches!(
            self,
            Self::MissingDescriptor
                | Self::ExtraDescriptor
                | Self::ReorderedDescriptors
                | Self::WrongDescriptorName
                | Self::WrongDescriptorType
                | Self::HigherDescriptor
        )
    }
}

pub fn dispatch(arguments: &[String]) -> Option<Result<(), String>> {
    if arguments
        .iter()
        .any(|argument| argument == "--release-launcher")
    {
        return Some(run_launcher(arguments));
    }
    if arguments
        .iter()
        .any(|argument| argument == "--release-adapter")
    {
        return Some(run_adapter(arguments));
    }
    if arguments
        .iter()
        .any(|argument| argument == "--release-barrier-proof")
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string());
        return Some(runtime.and_then(|runtime| runtime.block_on(run_provider(arguments))));
    }
    None
}

async fn run_provider(arguments: &[String]) -> Result<(), String> {
    let proof_case = ProofCase::parse(arguments)?;
    let mode = ExecutionMode::parse(arguments)?;
    if mode != ExecutionMode::Local && proof_case != ProofCase::Positive {
        return Err("negative barrier cases use the Local descriptor contract".to_owned());
    }
    let image = load_image_authority(arguments)?;
    let launch = build_launch_record(mode, image.sim1_digest)?;
    let channels = create_provider_channels(mode)?;

    let executable = std::env::current_exe().map_err(display_error)?;
    ensure_static_native_elf(&executable)?;
    let unit = format!(
        "pigloros-release-{}.service",
        hex::encode(launch.parameters.attempt_id)
    );
    let connection = zbus::Connection::system().await.map_err(display_error)?;
    let manager = zbus_systemd::systemd1::ManagerProxy::new(&connection)
        .await
        .map_err(display_error)?;
    let descriptor_set = descriptor_set(
        proof_case,
        channels.launcher_proxy,
        channels.launcher_release,
    )?;
    let extra_descriptors = descriptor_set
        .descriptors
        .into_iter()
        .map(|(name, descriptor)| (name, ZbusOwnedFd::from(descriptor)))
        .collect();
    let properties = transient_properties(
        &executable,
        &image.root_image,
        image.root_hash,
        image.root_signature,
        &launch.encoded_hex,
        mode,
        extra_descriptors,
    )?;
    manager
        .start_transient_unit(unit.clone(), "fail".to_owned(), properties, vec![])
        .await
        .map_err(display_error)?;

    // Keep the opposite endpoints of deliberately malformed descriptors alive
    // until systemd has consumed the request.
    let _retained_defect_peers = descriptor_set.retained_peers;

    let result = complete_release(
        &manager,
        &unit,
        &launch.parameters,
        &launch.encoded,
        &channels.provider_release,
        channels.provider_proxy.as_ref(),
        mode,
        proof_case,
    )
    .await;
    let _ = manager.stop_unit(unit.clone(), "replace".to_owned()).await;
    let _ = manager.reset_failed_unit(unit.clone()).await;
    if proof_case.is_descriptor_defect() {
        if result.is_ok() {
            return Err("descriptor defect unexpectedly reached release".to_owned());
        }
        ensure_no_adapter_marker(
            channels
                .provider_proxy
                .as_ref()
                .ok_or_else(|| "descriptor defect lacks Local proxy".to_owned())?,
        )?;
    } else {
        result?;
    }
    if proof_case == ProofCase::Positive && mode == ExecutionMode::Local {
        println!(
            "release_barrier=typed-local-release-ok;unit={unit};fd3=proxy-only;fd4=closed-before-adapter"
        );
    } else if proof_case == ProofCase::Positive {
        println!(
            "release_barrier=typed-{}-release-ok;unit={unit};release_fd3=closed-before-adapter;adapter_nonstdio=none",
            mode.name()
        );
    } else {
        println!(
            "release_barrier_negative={};adapter=unexecuted;unit=terminated",
            proof_case.name()
        );
    }
    Ok(())
}

fn build_launch_record(mode: ExecutionMode, sim1_digest: [u8; 32]) -> Result<LaunchRecord, String> {
    let expected_layout = FdLayout {
        mode: mode.ordinal(),
        entries: if mode == ExecutionMode::Local {
            vec![(3, 0), (4, 1)]
        } else {
            vec![(3, 1)]
        },
    };
    let parameters = LaunchParameters {
        attempt_id: random_bytes()?,
        nonce: random_bytes()?,
        sim1_digest,
        adapter_path: ADAPTER_PATH.to_owned(),
        adapter_arguments: vec![
            ADAPTER_PATH.to_owned(),
            "--release-adapter".to_owned(),
            format!("--mode={}", mode.name()),
        ],
        expected_fd_layout_digest: fd_layout_digest(&expected_layout)?,
    };
    let encoded = encode_launch_parameters(&parameters)?;
    let encoded_hex = hex::encode(&encoded);
    Ok(LaunchRecord {
        parameters,
        encoded,
        encoded_hex,
    })
}

fn create_provider_channels(mode: ExecutionMode) -> Result<ProviderChannels, String> {
    let (provider_proxy, launcher_proxy) = if mode == ExecutionMode::Local {
        let pair = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .map_err(display_error)?;
        (Some(pair.0), Some(pair.1))
    } else {
        (None, None)
    };
    let (provider_release, launcher_release) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(display_error)?;
    setsockopt(
        &launcher_release,
        sockopt::ReceiveTimeout,
        &TimeVal::seconds(2),
    )
    .map_err(display_error)?;
    configure_provider_sockets(&provider_release, provider_proxy.as_ref())?;
    Ok(ProviderChannels {
        provider_proxy,
        launcher_proxy,
        provider_release,
        launcher_release,
    })
}

fn configure_provider_sockets(release: &OwnedFd, proxy: Option<&OwnedFd>) -> Result<(), String> {
    setsockopt(release, sockopt::PassCred, &true).map_err(display_error)?;
    let receive_timeout = TimeVal::seconds(5);
    setsockopt(release, sockopt::ReceiveTimeout, &receive_timeout).map_err(display_error)?;
    if let Some(proxy) = proxy {
        setsockopt(proxy, sockopt::ReceiveTimeout, &receive_timeout).map_err(display_error)?;
    }
    Ok(())
}

fn load_image_authority(arguments: &[String]) -> Result<ImageAuthority, String> {
    let root_image = required_argument(arguments, "--root-image")?;
    let root_hash_path = required_argument(arguments, "--root-hash-file")?;
    let signature_path = required_argument(arguments, "--root-signature")?;
    let certificate_path = required_argument(arguments, "--root-certificate")?;
    let certificate_fingerprint = required_argument(arguments, "--certificate-fingerprint")?;
    verify_image_signature(
        root_hash_path,
        signature_path,
        certificate_path,
        certificate_fingerprint,
    )?;
    let root_hash_hex = std::fs::read_to_string(root_hash_path).map_err(display_error)?;
    let root_hash = hex::decode(root_hash_hex.trim()).map_err(display_error)?;
    if root_hash.len() != 32 {
        return Err("root hash is not 32 bytes".to_owned());
    }
    Ok(ImageAuthority {
        root_image: root_image.to_owned(),
        root_hash,
        root_signature: std::fs::read(signature_path).map_err(display_error)?,
        sim1_digest: digest_file(Path::new(root_image))?,
    })
}

fn descriptor_set(
    proof_case: ProofCase,
    launcher_proxy: Option<OwnedFd>,
    launcher_release: OwnedFd,
) -> Result<DescriptorSet, String> {
    let mut descriptors = match launcher_proxy {
        Some(proxy) => vec![
            (PROXY_NAME.to_owned(), proxy),
            (RELEASE_NAME.to_owned(), launcher_release),
        ],
        None => vec![(RELEASE_NAME.to_owned(), launcher_release)],
    };
    let mut retained_peers = Vec::new();
    match proof_case {
        ProofCase::MissingDescriptor => {
            descriptors.pop();
        }
        ProofCase::ExtraDescriptor | ProofCase::HigherDescriptor => {
            let (provider_extra, launcher_extra) = socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .map_err(display_error)?;
            retained_peers.push(provider_extra);
            descriptors.push(("unexpected-extra".to_owned(), launcher_extra));
        }
        ProofCase::ReorderedDescriptors => descriptors.swap(0, 1),
        ProofCase::WrongDescriptorName => {
            "wrong-host-service-name".clone_into(&mut descriptors[0].0);
        }
        ProofCase::WrongDescriptorType => {
            descriptors.pop();
            let (provider_wrong_type, launcher_wrong_type) = socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .map_err(display_error)?;
            retained_peers.push(provider_wrong_type);
            descriptors.push((RELEASE_NAME.to_owned(), launcher_wrong_type));
        }
        ProofCase::Positive
        | ProofCase::MalformedRelease
        | ProofCase::DuplicateRelease
        | ProofCase::ReorderedRelease
        | ProofCase::ReleaseTimeout
        | ProofCase::MismatchedRelease
        | ProofCase::ReplayedRelease
        | ProofCase::ExpiredRelease
        | ProofCase::ReadbackMismatch
        | ProofCase::Cancellation
        | ProofCase::ProviderEof
        | ProofCase::ProviderDeathHold => {}
    }
    Ok(DescriptorSet {
        descriptors,
        retained_peers,
    })
}

fn ensure_no_adapter_marker(proxy_socket: &OwnedFd) -> Result<(), String> {
    let mut marker = [0_u8; 64];
    match recv(
        proxy_socket.as_raw_fd(),
        &mut marker,
        MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(0) | Err(nix::errno::Errno::EAGAIN) => Ok(()),
        Ok(_) => Err("descriptor defect executed adapter bytes".to_owned()),
        Err(error) => Err(format!(
            "descriptor defect proxy observation failed: {error}"
        )),
    }
}

fn transient_properties(
    executable: &Path,
    root_image: &str,
    root_hash: Vec<u8>,
    root_signature: Vec<u8>,
    parameter_hex: &str,
    mode: ExecutionMode,
    extra_descriptors: Vec<(String, ZbusOwnedFd)>,
) -> Result<Vec<(String, OwnedValue)>, String> {
    let launcher_arguments = vec![
        RELEASE_LAUNCHER.to_owned(),
        "--release-launcher".to_owned(),
        format!("--mode={}", mode.name()),
        format!("--launch-parameters={parameter_hex}"),
    ];
    let bind = vec![(
        executable.display().to_string(),
        RELEASE_LAUNCHER.to_owned(),
        false,
        0_u64,
    )];
    let syscalls = flattened_system_service_syscalls()?;
    Ok(vec![
        property("Description", "PiglorOS ADR-069 release barrier proof")?,
        property("Type", "exec")?,
        property(
            "ExecStart",
            vec![(RELEASE_LAUNCHER.to_owned(), launcher_arguments, false)],
        )?,
        property("RootImage", root_image.to_owned())?,
        property("RootHash", root_hash)?,
        property("RootHashSignature", root_signature)?,
        property("RootImagePolicy", "root=verity+signed+read-only-on:=absent")?,
        // systemd v260.2 consumes bind mounts as a(ssbt): source,
        // destination, ignore-missing, and mount flags.
        property("BindReadOnlyPaths", bind)?,
        property("DynamicUser", true)?,
        property("NoNewPrivileges", true)?,
        property("PrivateDevices", true)?,
        property("PrivateIPC", true)?,
        property("PrivateMounts", true)?,
        property("PrivateNetwork", true)?,
        property("PrivatePIDs", "yes")?,
        property("PrivateUsersEx", "self")?,
        property("CapabilityBoundingSet", 0_u64)?,
        property("AmbientCapabilities", 0_u64)?,
        property("ProtectSystem", "strict")?,
        property("ProtectHome", "yes")?,
        property("ProtectControlGroupsEx", "strict")?,
        property("ProtectKernelTunables", true)?,
        property("ProtectKernelModules", true)?,
        property("ProtectKernelLogs", true)?,
        property("ProtectClock", true)?,
        property("ProtectHostname", true)?,
        property("ProtectProc", "invisible")?,
        property("ProcSubset", "pid")?,
        property("RestrictNamespaces", 0x7e02_0080_u64)?,
        property("RestrictSUIDSGID", true)?,
        property("RestrictRealtime", true)?,
        property("LockPersonality", true)?,
        property("SystemCallArchitectures", vec!["native".to_owned()])?,
        property("SystemCallFilter", (true, syscalls))?,
        property(
            "RestrictAddressFamilies",
            (
                true,
                if mode == ExecutionMode::Local {
                    vec!["AF_UNIX".to_owned()]
                } else {
                    Vec::<String>::new()
                },
            ),
        )?,
        property("UMask", 0o77_u32)?,
        property("KillMode", "control-group")?,
        property("SendSIGKILL", true)?,
        property("FileDescriptorStoreMax", 0_u32)?,
        descriptor_property("ExtraFileDescriptors", extra_descriptors)?,
    ])
}

async fn complete_release(
    manager: &zbus_systemd::systemd1::ManagerProxy<'_>,
    unit: &str,
    parameters: &LaunchParameters,
    encoded_parameters: &[u8],
    release_socket: &OwnedFd,
    proxy_socket: Option<&OwnedFd>,
    mode: ExecutionMode,
    proof_case: ProofCase,
) -> Result<(), String> {
    let (ready_bytes, credential_pid) = receive_ready(release_socket)?;
    let ready = crate::release_wire::decode_ready(&ready_bytes)?;
    let (main_pid, _namespace_descriptors) =
        validate_ready_state(unit, parameters, encoded_parameters, &ready, credential_pid)?;
    validate_requested_readback(unit, parameters, mode)?;
    let network = configure_network(main_pid, parameters.attempt_id, mode)?;
    if let Some(proxy_socket) = proxy_socket {
        ensure_adapter_blocked(proxy_socket)?;
    }

    if proof_case == ProofCase::ProviderDeathHold {
        println!("release_barrier_provider_ready;unit={unit};adapter=unexecuted");
        std::io::stdout().flush().map_err(display_error)?;
        loop {
            thread::park();
        }
    }

    if proof_case == ProofCase::Cancellation {
        manager
            .stop_unit(unit.to_owned(), "replace".to_owned())
            .await
            .map_err(display_error)?;
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }
    if proof_case == ProofCase::ProviderEof {
        shutdown(release_socket.as_raw_fd(), Shutdown::Both).map_err(display_error)?;
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }
    if proof_case == ProofCase::MalformedRelease {
        send_packet(release_socket.as_raw_fd(), b"not-canonical-release-v1")?;
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }
    if proof_case == ProofCase::ReleaseTimeout {
        thread::sleep(Duration::from_millis(2_250));
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }

    let release_bytes = build_release(parameters, &ready_bytes, &network, proof_case)?;
    let (_, release_digest, release_signature) = decode_release(&release_bytes)?;
    verify_release_signature(
        release_digest,
        release_signature,
        &proof_signing_key().verifying_key(),
    )?;
    let wire_bytes = if proof_case == ProofCase::ReorderedRelease {
        reorder_release_fields(&release_bytes)?
    } else {
        release_bytes
    };
    send_packet(release_socket.as_raw_fd(), &wire_bytes)?;
    if proof_case == ProofCase::DuplicateRelease {
        let _ = send_packet(release_socket.as_raw_fd(), &wire_bytes);
    }

    if proof_case != ProofCase::Positive {
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }

    if let Some(proxy_socket) = proxy_socket {
        let mut marker = [0_u8; 64];
        let count = recv(proxy_socket.as_raw_fd(), &mut marker, MsgFlags::empty())
            .map_err(display_error)?;
        if &marker[..count] != b"ADAPTER_EXECUTED_FD3" {
            return Err("adapter did not retain exactly the Local proxy on FD 3".to_owned());
        }
    }
    wait_for_unit_terminal(manager, unit).await
}

fn required_proxy(proxy: Option<&OwnedFd>) -> Result<&OwnedFd, String> {
    proxy.ok_or_else(|| "negative release case lacks Local proxy".to_owned())
}

fn ensure_adapter_blocked(proxy_socket: &OwnedFd) -> Result<(), String> {
    let mut premature_marker = [0_u8; 64];
    match recv(
        proxy_socket.as_raw_fd(),
        &mut premature_marker,
        MsgFlags::MSG_DONTWAIT,
    ) {
        Err(nix::errno::Errno::EAGAIN) => Ok(()),
        Ok(0) => Err("Local proxy closed before release".to_owned()),
        Ok(_) => Err("adapter executed before ReleaseV1".to_owned()),
        Err(error) => Err(format!("Local proxy pre-release probe failed: {error}")),
    }
}

fn validate_ready_state(
    unit: &str,
    parameters: &LaunchParameters,
    encoded_parameters: &[u8],
    ready: &Ready,
    credential_pid: u32,
) -> Result<(u32, Vec<File>), String> {
    let main_pid = wait_for_main_pid(unit)?;
    if credential_pid != main_pid
        || ready.attempt_id != parameters.attempt_id
        || ready.nonce != parameters.nonce
        || ready.sim1_digest != parameters.sim1_digest
        || ready.launch_parameter_digest != launch_parameter_digest(encoded_parameters)?
        || ready.expected_fd_layout_digest != parameters.expected_fd_layout_digest
        || ready.observed_fd_layout_digest != parameters.expected_fd_layout_digest
    {
        return Err("ReadyV1 binding or SCM_CREDENTIALS mismatch".to_owned());
    }
    let invocation_id = unit_property(unit, "InvocationID")?;
    if ready.invocation_id != decode_fixed_hex(invocation_id.trim())? {
        return Err("ReadyV1 invocation ID mismatch".to_owned());
    }
    validate_ready_executables(main_pid, ready)?;
    let namespaces = retain_and_validate_namespaces(main_pid)?;
    Ok((main_pid, namespaces))
}

fn build_release(
    parameters: &LaunchParameters,
    ready_bytes: &[u8],
    local_network: &LocalNetworkGuard,
    proof_case: ProofCase,
) -> Result<Vec<u8>, String> {
    let mut release = Release {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        ready_digest: ready_digest(ready_bytes)?,
        trs1_digest: proof_digest("TRS1-proof"),
        rvs1_digest: proof_digest("RVS1-proof"),
        apt1_digest: proof_digest("APT1-proof"),
        trust_epoch: 7,
        revocation_epoch: 11,
        policy_epoch: 13,
        expected_readback_digest: local_network.expected_readback_digest,
        observed_readback_digest: local_network.observed_readback_digest,
        deadline_monotonic_ns: monotonic_ns()?.saturating_add(5_000_000_000),
        runtime_key_id: "adr069-proof-runtime-key".to_owned(),
    };
    match proof_case {
        ProofCase::MismatchedRelease => release.nonce[0] ^= 1,
        ProofCase::ReplayedRelease => release.attempt_id = [0xa5; 16],
        ProofCase::ExpiredRelease => {
            release.deadline_monotonic_ns = monotonic_ns()?.saturating_sub(1);
        }
        ProofCase::ReadbackMismatch => release.observed_readback_digest[0] ^= 1,
        ProofCase::Positive
        | ProofCase::MalformedRelease
        | ProofCase::DuplicateRelease
        | ProofCase::ReorderedRelease
        | ProofCase::ReleaseTimeout
        | ProofCase::Cancellation
        | ProofCase::ProviderEof
        | ProofCase::ProviderDeathHold
        | ProofCase::MissingDescriptor
        | ProofCase::ExtraDescriptor
        | ProofCase::ReorderedDescriptors
        | ProofCase::WrongDescriptorName
        | ProofCase::WrongDescriptorType
        | ProofCase::HigherDescriptor => {}
    }
    crate::release_wire::encode_release(&release, &proof_signing_key())
}

fn confirm_negative_termination(unit: &str, proxy_socket: &OwnedFd) -> Result<(), String> {
    let mut marker = [0_u8; 64];
    match recv(proxy_socket.as_raw_fd(), &mut marker, MsgFlags::empty()) {
        Ok(0) | Err(nix::errno::Errno::EAGAIN) => {}
        Ok(_) => return Err("negative case executed adapter bytes".to_owned()),
        Err(error) => return Err(format!("negative proxy observation failed: {error}")),
    }
    let status = wait_for_terminal_status(unit)?;
    if status == 0 {
        return Err("negative release case exited successfully".to_owned());
    }
    Ok(())
}

fn run_launcher(arguments: &[String]) -> Result<(), String> {
    let mode = ExecutionMode::parse(arguments)?;
    let encoded =
        hex::decode(required_argument(arguments, "--launch-parameters")?).map_err(display_error)?;
    let parameters = decode_launch_parameters(&encoded)?;
    let named_descriptors = if mode == ExecutionMode::Local {
        vec![(3, PROXY_NAME), (4, RELEASE_NAME)]
    } else {
        vec![(3, RELEASE_NAME)]
    };
    let typed_descriptors = if mode == ExecutionMode::Local {
        vec![(3, SockType::Stream), (4, SockType::SeqPacket)]
    } else {
        vec![(3, SockType::SeqPacket)]
    };
    validate_systemd_descriptor_environment(&named_descriptors)?;
    let observed = observed_layout(mode.ordinal(), &typed_descriptors)?;
    if fd_layout_digest(&observed)? != parameters.expected_fd_layout_digest {
        return Err("observed descriptor layout does not match LPV1".to_owned());
    }

    let (proxy, release) = if mode == ExecutionMode::Local {
        (Some(take_inherited_fd(3)?), take_inherited_fd(4)?)
    } else {
        (None, take_inherited_fd(3)?)
    };
    let provider_credentials =
        getsockopt(&release, sockopt::PeerCredentials).map_err(display_error)?;
    if provider_credentials.uid() != 0 {
        return Err("release peer is not the root provider".to_owned());
    }
    if let Some(proxy) = &proxy {
        set_close_on_exec(proxy, true)?;
    }
    set_close_on_exec(&release, true)?;
    let adapter = open_native_adapter(&parameters.adapter_path)?;
    let ready = build_ready(&parameters, &encoded, &adapter, &observed)?;
    let ready_bytes = encode_ready(&ready)?;
    send_packet(release.as_raw_fd(), &ready_bytes)?;

    let release_bytes = receive_packet(release.as_raw_fd())?;
    reject_queued_release(release.as_raw_fd())?;
    let (release_record, digest, _signature) = decode_release(&release_bytes)?;
    if release_record.attempt_id != parameters.attempt_id
        || release_record.nonce != parameters.nonce
        || release_record.ready_digest != ready_digest(&ready_bytes)?
        || release_record.expected_readback_digest != release_record.observed_readback_digest
        || release_record.deadline_monotonic_ns < monotonic_ns()?
        || digest == [0; 32]
    {
        return Err("ReleaseV1 binding, state, or deadline mismatch".to_owned());
    }
    drop(release);
    if let Some(proxy) = &proxy {
        set_close_on_exec(proxy, false)?;
    }
    exec_adapter(&adapter, &parameters.adapter_arguments)
}

fn reject_queued_release(descriptor: RawFd) -> Result<(), String> {
    thread::sleep(Duration::from_millis(25));
    let mut packet = [0_u8; 1];
    match recv(
        descriptor,
        &mut packet,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
    ) {
        Err(nix::errno::Errno::EAGAIN) => Ok(()),
        Ok(_) => Err("duplicate ReleaseV1 packet is queued".to_owned()),
        Err(error) => Err(format!("ReleaseV1 duplicate probe failed: {error}")),
    }
}

fn reorder_release_fields(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let mut value: ciborium::value::Value =
        ciborium::from_reader(encoded).map_err(display_error)?;
    let outer = value
        .as_array_mut()
        .ok_or_else(|| "ReleaseV1 wrapper is not an array".to_owned())?;
    let prefix = outer
        .first_mut()
        .and_then(ciborium::value::Value::as_array_mut)
        .ok_or_else(|| "ReleaseV1 prefix is not an array".to_owned())?;
    if prefix.len() < 4 {
        return Err("ReleaseV1 prefix is too short to reorder".to_owned());
    }
    prefix.swap(2, 3);
    let mut reordered = Vec::new();
    ciborium::into_writer(&value, &mut reordered).map_err(display_error)?;
    Ok(reordered)
}

fn run_adapter(arguments: &[String]) -> Result<(), String> {
    let mode = ExecutionMode::parse(arguments)?;
    if std::env::vars_os().next().is_some() {
        return Err("adapter environment was not empty".to_owned());
    }
    let descriptors = open_non_stdio_descriptors()?;
    if mode == ExecutionMode::Local
        && (descriptors != vec![3] || socket_type(3)? != SockType::Stream)
    {
        return Err(format!(
            "adapter descriptor set is not exactly FD 3: {descriptors:?}"
        ));
    }
    if mode != ExecutionMode::Local && !descriptors.is_empty() {
        return Err(format!(
            "{} adapter inherited non-stdio descriptors: {descriptors:?}",
            mode.name()
        ));
    }
    if mode == ExecutionMode::Local
        && send(3, b"ADAPTER_EXECUTED_FD3", MsgFlags::empty()).map_err(display_error)? != 20
    {
        return Err("adapter FD 3 marker was truncated".to_owned());
    }
    Ok(())
}

fn build_ready(
    parameters: &LaunchParameters,
    encoded_parameters: &[u8],
    adapter: &File,
    observed: &FdLayout,
) -> Result<Ready, String> {
    let launcher = File::open("/proc/self/exe").map_err(display_error)?;
    Ok(Ready {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        invocation_id: decode_fixed_hex(&std::env::var("INVOCATION_ID").map_err(display_error)?)?,
        launcher_digest: digest_reader(&launcher)?,
        launcher_identity: descriptor_identity(&launcher)?,
        sim1_digest: parameters.sim1_digest,
        adapter_digest: digest_reader(adapter)?,
        adapter_identity: descriptor_identity(adapter)?,
        launch_parameter_digest: launch_parameter_digest(encoded_parameters)?,
        expected_fd_layout_digest: parameters.expected_fd_layout_digest,
        observed_fd_layout_digest: fd_layout_digest(observed)?,
    })
}

fn open_native_adapter(path: &str) -> Result<File, String> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("adapter path is not normalized absolute".to_owned());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(display_error)?;
    if !file.metadata().map_err(display_error)?.is_file() {
        return Err("adapter is not a regular file".to_owned());
    }
    ensure_native_elf_file(&file)?;
    Ok(file)
}

fn ensure_static_native_elf(path: &Path) -> Result<(), String> {
    let mut file = File::open(path).map_err(display_error)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(display_error)?;
    ensure_native_elf(&bytes)?;
    let program_header_offset = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().map_err(display_error)?,
    ))
    .map_err(display_error)?;
    let program_header_size = usize::from(u16::from_le_bytes(
        bytes[54..56].try_into().map_err(display_error)?,
    ));
    let program_header_count = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().map_err(display_error)?,
    ));
    if program_header_size < 4
        || (0..program_header_count).any(|index| {
            program_header_offset
                .checked_add(index.saturating_mul(program_header_size))
                .and_then(|offset| bytes.get(offset..offset.saturating_add(4)))
                .is_some_and(|kind| kind == 3_u32.to_le_bytes())
        })
    {
        return Err("launcher is dynamically interpreted".to_owned());
    }
    Ok(())
}

fn ensure_native_elf_file(file: &File) -> Result<(), String> {
    let mut file = file.try_clone().map_err(display_error)?;
    file.seek(SeekFrom::Start(0)).map_err(display_error)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header).map_err(display_error)?;
    ensure_native_elf(&header)
}

fn ensure_native_elf(header: &[u8]) -> Result<(), String> {
    if header.len() < 64 || header[..4] != *b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return Err("executable is not little-endian ELF".to_owned());
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let expected = match std::env::consts::ARCH {
        "x86_64" => 62,
        "aarch64" => 183,
        architecture => return Err(format!("unsupported architecture {architecture}")),
    };
    if machine != expected {
        return Err("ELF architecture does not match the host".to_owned());
    }
    Ok(())
}

fn validate_systemd_descriptor_environment(expected: &[(RawFd, &str)]) -> Result<(), String> {
    let listen_pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let listen_fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if listen_pid != Some(std::process::id()) || listen_fds != Some(expected.len()) {
        return Err("systemd descriptor count or PID mismatch".to_owned());
    }
    let names = std::env::var("LISTEN_FDNAMES").map_err(display_error)?;
    if names.split(':').ne(expected.iter().map(|(_, name)| *name)) {
        return Err("systemd descriptor names or order mismatch".to_owned());
    }
    Ok(())
}

fn observed_layout(mode: u8, expected: &[(RawFd, SockType)]) -> Result<FdLayout, String> {
    let descriptors = open_non_stdio_descriptors()?;
    if descriptors != expected.iter().map(|(fd, _)| *fd).collect::<Vec<_>>() {
        return Err(format!("unexpected inherited descriptors: {descriptors:?}"));
    }
    let mut entries = Vec::new();
    for &(descriptor, expected_type) in expected {
        if socket_type(descriptor)? != expected_type {
            return Err(format!("descriptor {descriptor} has the wrong socket type"));
        }
        entries.push((
            u64::try_from(descriptor).map_err(display_error)?,
            u8::from(expected_type != SockType::Stream),
        ));
    }
    Ok(FdLayout { mode, entries })
}

fn open_non_stdio_descriptors() -> Result<Vec<RawFd>, String> {
    let (soft_limit, _) = getrlimit(Resource::RLIMIT_NOFILE).map_err(display_error)?;
    let upper = if soft_limit == RLIM_INFINITY {
        1_048_576
    } else {
        soft_limit.min(1_048_576)
    };
    let upper = i32::try_from(upper).map_err(display_error)?;
    Ok((3..upper).filter(|&fd| descriptor_is_open(fd)).collect())
}

#[allow(unsafe_code)]
fn descriptor_is_open(descriptor: RawFd) -> bool {
    // SAFETY: the borrow lives only for this fcntl call. An arbitrary numeric
    // descriptor is permitted; EBADF is precisely how the complete scan marks
    // a closed slot.
    let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
    fcntl(borrowed, FcntlArg::F_GETFD).is_ok()
}

#[allow(unsafe_code)]
fn take_inherited_fd(descriptor: RawFd) -> Result<OwnedFd, String> {
    if !descriptor_is_open(descriptor) {
        return Err(format!("inherited descriptor {descriptor} is closed"));
    }
    // SAFETY: descriptor topology was exhaustively validated and this function
    // is called exactly once for each inherited descriptor, transferring its
    // ownership to the returned OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[allow(unsafe_code)]
fn socket_type(descriptor: RawFd) -> Result<SockType, String> {
    // SAFETY: this non-owning borrow is bounded to getsockopt.
    let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
    getsockopt(&borrowed, sockopt::SockType).map_err(display_error)
}

fn set_close_on_exec(descriptor: &OwnedFd, close: bool) -> Result<(), String> {
    let flags = if close {
        FdFlag::FD_CLOEXEC
    } else {
        FdFlag::empty()
    };
    fcntl(descriptor, FcntlArg::F_SETFD(flags))
        .map(|_| ())
        .map_err(display_error)
}

fn exec_adapter(adapter: &File, arguments: &[String]) -> Result<(), String> {
    let arguments = arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()).map_err(display_error))
        .collect::<Result<Vec<_>, _>>()?;
    let empty_path = CString::new("").map_err(display_error)?;
    let empty_environment: Vec<CString> = Vec::new();
    execveat(
        adapter,
        &empty_path,
        &arguments,
        &empty_environment,
        AtFlags::AT_EMPTY_PATH,
    )
    .map(|never| match never {})
    .map_err(display_error)
}

fn receive_ready(socket: &OwnedFd) -> Result<(Vec<u8>, u32), String> {
    let mut bytes = vec![0_u8; MAX_PACKET];
    let mut control = nix::cmsg_space!(nix::sys::socket::UnixCredentials);
    let (count, credential_pid) = {
        let mut iov = [IoSliceMut::new(&mut bytes)];
        let message = recvmsg::<()>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        )
        .map_err(display_error)?;
        if message.flags.contains(MsgFlags::MSG_TRUNC) || message.bytes == 0 {
            return Err("ReadyV1 packet is empty or truncated".to_owned());
        }
        let mut credential_pid = None;
        for control_message in message.cmsgs().map_err(display_error)? {
            if let ControlMessageOwned::ScmCredentials(credentials) = control_message {
                credential_pid = u32::try_from(credentials.pid()).ok();
            }
        }
        (message.bytes, credential_pid)
    };
    bytes.truncate(count);
    Ok((
        bytes,
        credential_pid.ok_or_else(|| "ReadyV1 lacks SCM_CREDENTIALS".to_owned())?,
    ))
}

fn receive_packet(descriptor: RawFd) -> Result<Vec<u8>, String> {
    let mut packet = vec![0_u8; MAX_PACKET];
    let count = recv(descriptor, &mut packet, MsgFlags::empty()).map_err(display_error)?;
    if count == 0 || count == MAX_PACKET {
        return Err("release packet is empty or at its bound".to_owned());
    }
    packet.truncate(count);
    Ok(packet)
}

fn send_packet(descriptor: RawFd, packet: &[u8]) -> Result<(), String> {
    if packet.is_empty() || packet.len() > MAX_PACKET {
        return Err("packet is outside the bound".to_owned());
    }
    if send(descriptor, packet, MsgFlags::empty()).map_err(display_error)? != packet.len() {
        return Err("packet send was truncated".to_owned());
    }
    Ok(())
}

fn descriptor_identity(file: &File) -> Result<FdIdentity, String> {
    let metadata = file.metadata().map_err(display_error)?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(display_error)?;
    let mount_id = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .ok_or_else(|| "descriptor mount ID is absent".to_owned())?
        .parse()
        .map_err(display_error)?;
    Ok(FdIdentity {
        mount_id,
        inode: metadata.ino(),
    })
}

fn digest_reader(file: &File) -> Result<[u8; 32], String> {
    let mut reader = file.try_clone().map_err(display_error)?;
    reader.seek(SeekFrom::Start(0)).map_err(display_error)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(display_error)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn digest_file(path: &Path) -> Result<[u8; 32], String> {
    digest_reader(&File::open(path).map_err(display_error)?)
}

fn verify_image_signature(
    root_hash: &str,
    signature: &str,
    certificate: &str,
    expected_fingerprint: &str,
) -> Result<(), String> {
    let verification = Command::new("openssl")
        .args([
            "smime",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            signature,
            "-content",
            root_hash,
            "-CAfile",
            certificate,
            "-purpose",
            "any",
            "-out",
            "/dev/null",
        ])
        .status()
        .map_err(display_error)?;
    if !verification.success() {
        return Err("PKCS#7 verification failed before StartTransientUnit".to_owned());
    }
    let fingerprint = Command::new("openssl")
        .args([
            "x509",
            "-in",
            certificate,
            "-noout",
            "-fingerprint",
            "-sha256",
        ])
        .output()
        .map_err(display_error)?;
    if !fingerprint.status.success() {
        return Err("certificate fingerprint failed".to_owned());
    }
    let observed = String::from_utf8(fingerprint.stdout).map_err(display_error)?;
    let observed = observed
        .trim()
        .split_once('=')
        .map(|(_, value)| value.replace(':', ""))
        .ok_or_else(|| "certificate fingerprint is malformed".to_owned())?;
    if !observed.eq_ignore_ascii_case(expected_fingerprint) {
        return Err("certificate is not authorized by proof TRS1".to_owned());
    }
    Ok(())
}

fn retain_and_validate_namespaces(main_pid: u32) -> Result<Vec<File>, String> {
    let mut descriptors = Vec::new();
    let mut evidence = Vec::new();
    for namespace in ["mnt", "pid", "ipc", "uts", "user", "net"] {
        let provider_path = format!("/proc/self/ns/{namespace}");
        let launcher_path = format!("/proc/{main_pid}/ns/{namespace}");
        let provider = std::fs::read_link(&provider_path).map_err(display_error)?;
        let launcher = std::fs::read_link(&launcher_path).map_err(display_error)?;
        if provider == launcher {
            return Err(format!("{namespace} namespace was not isolated"));
        }
        let descriptor = File::open(&launcher_path).map_err(display_error)?;
        let descriptor_inode = descriptor.metadata().map_err(display_error)?.ino();
        let linked_inode = namespace_link_inode(&launcher)?;
        if descriptor_inode != linked_inode {
            return Err(format!("{namespace} namespace descriptor identity changed"));
        }
        evidence.push(format!(
            "{namespace}:provider={};launcher={};fd_inode={descriptor_inode}",
            provider.display(),
            launcher.display()
        ));
        descriptors.push(descriptor);
    }
    println!(
        "namespace_descriptors=retained-and-validated;{}",
        evidence.join(";")
    );
    Ok(descriptors)
}

fn namespace_link_inode(link: &Path) -> Result<u64, String> {
    let value = link
        .to_str()
        .ok_or_else(|| "namespace link is not UTF-8".to_owned())?;
    value
        .strip_suffix(']')
        .and_then(|value| value.rsplit_once('['))
        .map(|(_, inode)| inode)
        .ok_or_else(|| format!("invalid namespace identity {value}"))?
        .parse()
        .map_err(display_error)
}

fn configure_local_network(
    main_pid: u32,
    attempt_id: [u8; 16],
) -> Result<LocalNetworkGuard, String> {
    let suffix = &hex::encode(attempt_id)[..8];
    let host_interface = format!("pgh{suffix}");
    let guest_interface = format!("pgg{suffix}");
    let table = format!("pgr{suffix}");
    run_command(
        Command::new("ip").args([
            "link",
            "add",
            "name",
            &host_interface,
            "type",
            "veth",
            "peer",
            "name",
            &guest_interface,
        ]),
        "create Local veth",
    )?;
    let mut guard = LocalNetworkGuard {
        host_interface: Some(host_interface.clone()),
        expected_readback_digest: [0; 32],
        observed_readback_digest: [0; 32],
    };
    let pid = main_pid.to_string();
    run_command(
        Command::new("ip").args(["link", "set", &guest_interface, "netns", &pid]),
        "move Local veth peer",
    )?;
    run_command(
        Command::new("ip").args(["address", "add", "192.0.2.1/30", "dev", &host_interface]),
        "address Local host veth",
    )?;
    run_command(
        Command::new("ip").args(["link", "set", "dev", &host_interface, "up"]),
        "raise Local host veth",
    )?;
    run_in_network_namespace(&pid, ["ip", "link", "set", "dev", "lo", "up"])?;
    run_in_network_namespace(
        &pid,
        [
            "ip",
            "address",
            "add",
            "192.0.2.2/30",
            "dev",
            &guest_interface,
        ],
    )?;
    run_in_network_namespace(&pid, ["ip", "link", "set", "dev", &guest_interface, "up"])?;
    install_local_firewall(&pid, &table)?;

    let raw_readback = read_local_network(&pid, &host_interface, &guest_interface, &table)?;
    validate_local_network_readback(&raw_readback, &host_interface, &guest_interface, &table)?;
    let canonical = format!(
        "local-network-v1;host={host_interface};host-address=192.0.2.1/30;guest={guest_interface};guest-address=192.0.2.2/30;default-route=absent;table=inet/{table};input=drop;output=drop;forward=drop;adapter-network=fd3-proxy-only"
    );
    guard.expected_readback_digest = *blake3::hash(canonical.as_bytes()).as_bytes();
    guard.observed_readback_digest = *blake3::hash(canonical.as_bytes()).as_bytes();
    println!(
        "local_network_readback_begin\n{raw_readback}\ncanonical={canonical}\ndigest={}\nlocal_network_readback_end",
        hex::encode(guard.observed_readback_digest)
    );
    Ok(guard)
}

fn configure_network(
    main_pid: u32,
    attempt_id: [u8; 16],
    mode: ExecutionMode,
) -> Result<LocalNetworkGuard, String> {
    if mode == ExecutionMode::Local {
        return configure_local_network(main_pid, attempt_id);
    }
    configure_closed_network(main_pid, attempt_id, mode)
}

fn configure_closed_network(
    main_pid: u32,
    attempt_id: [u8; 16],
    mode: ExecutionMode,
) -> Result<LocalNetworkGuard, String> {
    let suffix = &hex::encode(attempt_id)[..8];
    let table = format!("pgr{suffix}");
    let pid = main_pid.to_string();
    install_closed_firewall(&pid, &table)?;
    let links = network_namespace_output(&pid, ["ip", "-oneline", "link", "show"])?;
    let default_route =
        network_namespace_output(&pid, ["ip", "-oneline", "route", "show", "default"])?;
    let ruleset = network_namespace_output(&pid, ["nft", "list", "table", "inet", &table])?;
    if links.lines().any(|line| !line.contains(": lo:"))
        || !default_route.is_empty()
        || ruleset.matches("policy drop").count() != 3
        || !ruleset.contains(&format!("table inet {table}"))
        || ruleset.contains(" accept")
    {
        return Err(format!(
            "{} network namespace differs from the closed policy",
            mode.name()
        ));
    }
    let canonical = format!(
        "closed-network-v1;mode={};external-interface=absent;default-route=absent;table=inet/{table};input=drop;output=drop;forward=drop;adapter-nonstdio=none",
        mode.name()
    );
    let digest = *blake3::hash(canonical.as_bytes()).as_bytes();
    println!(
        "closed_network_readback_begin\nmode={}\nlinks={links}\ndefault_route={default_route}\nruleset=\n{ruleset}\ncanonical={canonical}\ndigest={}\nclosed_network_readback_end",
        mode.name(),
        hex::encode(digest)
    );
    Ok(LocalNetworkGuard {
        host_interface: None,
        expected_readback_digest: digest,
        observed_readback_digest: digest,
    })
}

fn install_local_firewall(pid: &str, table: &str) -> Result<(), String> {
    let rules = format!(
        "table inet {table} {{\n chain input {{ type filter hook input priority 0; policy drop; iifname \"lo\" accept; }}\n chain output {{ type filter hook output priority 0; policy drop; oifname \"lo\" accept; }}\n chain forward {{ type filter hook forward priority 0; policy drop; }}\n}}\n"
    );
    install_firewall(pid, &rules)
}

fn install_closed_firewall(pid: &str, table: &str) -> Result<(), String> {
    let rules = format!(
        "table inet {table} {{\n chain input {{ type filter hook input priority 0; policy drop; }}\n chain output {{ type filter hook output priority 0; policy drop; }}\n chain forward {{ type filter hook forward priority 0; policy drop; }}\n}}\n"
    );
    install_firewall(pid, &rules)
}

fn install_firewall(pid: &str, rules: &str) -> Result<(), String> {
    let mut child = Command::new("nsenter")
        .args(["--target", pid, "--net", "--", "nft", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(display_error)?;
    child
        .stdin
        .take()
        .ok_or_else(|| "nftables stdin was not piped".to_owned())?
        .write_all(rules.as_bytes())
        .map_err(display_error)?;
    let output = child.wait_with_output().map_err(display_error)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "install nftables rules: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn read_local_network(
    pid: &str,
    host_interface: &str,
    guest_interface: &str,
    table: &str,
) -> Result<String, String> {
    let host_link = command_output(
        Command::new("ip").args(["-details", "-oneline", "link", "show", host_interface]),
        "read Local host link",
    )?;
    let host_address = command_output(
        Command::new("ip").args(["-oneline", "-4", "address", "show", host_interface]),
        "read Local host address",
    )?;
    let guest_link = network_namespace_output(
        pid,
        [
            "ip",
            "-details",
            "-oneline",
            "link",
            "show",
            guest_interface,
        ],
    )?;
    let guest_address = network_namespace_output(
        pid,
        ["ip", "-oneline", "-4", "address", "show", guest_interface],
    )?;
    let default_route =
        network_namespace_output(pid, ["ip", "-oneline", "route", "show", "default"])?;
    let ruleset = network_namespace_output(pid, ["nft", "list", "table", "inet", table])?;
    Ok(format!(
        "host_link={host_link}\nhost_address={host_address}\nguest_link={guest_link}\nguest_address={guest_address}\ndefault_route={default_route}\nruleset=\n{ruleset}"
    ))
}

fn validate_local_network_readback(
    readback: &str,
    host_interface: &str,
    guest_interface: &str,
    table: &str,
) -> Result<(), String> {
    let required = [
        host_interface.to_owned(),
        guest_interface.to_owned(),
        "state UP".to_owned(),
        "192.0.2.1/30".to_owned(),
        "192.0.2.2/30".to_owned(),
        format!("table inet {table}"),
        "hook input".to_owned(),
        "hook output".to_owned(),
        "hook forward".to_owned(),
        "iifname \"lo\" accept".to_owned(),
        "oifname \"lo\" accept".to_owned(),
    ];
    if required.iter().any(|value| !readback.contains(value))
        || readback.matches("policy drop").count() != 3
        || !readback.contains("default_route=\nruleset=")
    {
        return Err("Local veth/nftables readback differs from the closed policy".to_owned());
    }
    Ok(())
}

fn run_in_network_namespace<const N: usize>(pid: &str, arguments: [&str; N]) -> Result<(), String> {
    run_command(
        Command::new("nsenter")
            .args(["--target", pid, "--net", "--"])
            .args(arguments),
        "configure Local network namespace",
    )
}

fn network_namespace_output<const N: usize>(
    pid: &str,
    arguments: [&str; N],
) -> Result<String, String> {
    command_output(
        Command::new("nsenter")
            .args(["--target", pid, "--net", "--"])
            .args(arguments),
        "read Local network namespace",
    )
}

fn run_command(command: &mut Command, label: &str) -> Result<(), String> {
    command_output(command, label).map(|_| ())
}

fn command_output(command: &mut Command, label: &str) -> Result<String, String> {
    let output = command.output().map_err(display_error)?;
    if !output.status.success() {
        return Err(format!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(display_error)
}

fn validate_ready_executables(main_pid: u32, ready: &Ready) -> Result<(), String> {
    let expected_digest = digest_file(&std::env::current_exe().map_err(display_error)?)?;
    let process_executable = Path::new("/proc").join(main_pid.to_string()).join("exe");
    let observed_digest = digest_file(&process_executable)?;
    let observed_inode = std::fs::metadata(&process_executable)
        .map_err(display_error)?
        .ino();
    let mountinfo =
        std::fs::read_to_string(format!("/proc/{main_pid}/mountinfo")).map_err(display_error)?;
    let launcher_mount_id = mountinfo
        .lines()
        .find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.get(4) == Some(&RELEASE_LAUNCHER)).then(|| fields[0].parse())
        })
        .transpose()
        .map_err(display_error)?
        .ok_or_else(|| "launcher bind mount is absent from mountinfo".to_owned())?;
    if ready.launcher_digest != expected_digest
        || observed_digest != expected_digest
        || ready.adapter_digest != expected_digest
        || ready.launcher_identity.inode != observed_inode
        || ready.launcher_identity.mount_id != launcher_mount_id
        || ready.adapter_identity == ready.launcher_identity
    {
        return Err("ReadyV1 executable identity mismatch".to_owned());
    }
    Ok(())
}

fn validate_requested_readback(
    unit: &str,
    parameters: &LaunchParameters,
    mode: ExecutionMode,
) -> Result<(), String> {
    let properties = [
        ("Type", "exec"),
        ("RootImagePolicy", "root=verity+signed+read-only-on:=absent"),
        ("DynamicUser", "yes"),
        ("NoNewPrivileges", "yes"),
        ("PrivateDevices", "yes"),
        ("PrivateIPC", "yes"),
        ("PrivateMounts", "yes"),
        ("PrivateNetwork", "yes"),
        ("PrivatePIDs", "yes"),
        ("FileDescriptorStoreMax", "0"),
    ];
    for (name, expected) in properties {
        if unit_property(unit, name)?.trim() != expected {
            return Err(format!("{name} readback mismatch"));
        }
    }
    let command = unit_property(unit, "ExecStart")?;
    if !command.contains(RELEASE_LAUNCHER)
        || !command.contains("--release-launcher")
        || !command.contains(&format!("--mode={}", mode.name()))
        || !command.contains(&hex::encode(encode_launch_parameters(parameters)?))
    {
        return Err("ExecStart readback mismatch".to_owned());
    }
    Ok(())
}

fn wait_for_main_pid(unit: &str) -> Result<u32, String> {
    for _ in 0..100 {
        if let Ok(pid) = unit_property(unit, "MainPID")
            .and_then(|pid| pid.trim().parse::<u32>().map_err(display_error))
        {
            if pid > 1 {
                return Ok(pid);
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("transient unit did not expose MainPID".to_owned())
}

fn unit_property(unit: &str, property_name: &str) -> Result<String, String> {
    let output = Command::new("systemctl")
        .args(["show", unit, "--property", property_name, "--value"])
        .output()
        .map_err(display_error)?;
    if !output.status.success() {
        return Err(format!("failed to read unit property {property_name}"));
    }
    String::from_utf8(output.stdout).map_err(display_error)
}

async fn wait_for_unit_terminal(
    manager: &zbus_systemd::systemd1::ManagerProxy<'_>,
    unit: &str,
) -> Result<(), String> {
    match wait_for_terminal_status(unit) {
        Ok(0) => Ok(()),
        Ok(status) => Err(format!("adapter exited with status {status}")),
        Err(error) => {
            let _ = manager
                .stop_unit(unit.to_owned(), "replace".to_owned())
                .await;
            Err(error)
        }
    }
}

fn wait_for_terminal_status(unit: &str) -> Result<i32, String> {
    for _ in 0..250 {
        let active = unit_property(unit, "ActiveState")?;
        if matches!(active.trim(), "inactive" | "failed") {
            return unit_property(unit, "ExecMainStatus")?
                .trim()
                .parse()
                .map_err(display_error);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("transient unit did not terminate".to_owned())
}

fn flattened_system_service_syscalls() -> Result<Vec<String>, String> {
    let output = Command::new("systemd-analyze")
        .args(["syscall-filter", "@system-service"])
        .output()
        .map_err(display_error)?;
    if !output.status.success() {
        return Err("failed to flatten @system-service".to_owned());
    }
    let mut names = String::from_utf8(output.stdout)
        .map_err(display_error)?
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with('@')
                && line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    if names.is_empty() {
        return Err("flattened syscall set is empty".to_owned());
    }
    Ok(names)
}

fn property<T>(name: &str, value: T) -> Result<(String, OwnedValue), String>
where
    T: zbus::zvariant::Type + Into<zbus::zvariant::Value<'static>>,
{
    let value = zbus::zvariant::Value::new(value)
        .try_into_owned()
        .map_err(display_error)?;
    Ok((name.to_owned(), value))
}

fn descriptor_property(
    name: &str,
    descriptors: Vec<(String, ZbusOwnedFd)>,
) -> Result<(String, OwnedValue), String> {
    let mut structures = descriptors
        .into_iter()
        .map(|(descriptor_name, descriptor)| {
            // systemd v260.2 consumes ExtraFileDescriptors as a(hs): the
            // Unix descriptor precedes its activation name.
            StructureBuilder::new()
                .append_field(ZbusValue::Fd(descriptor.into()))
                .append_field(descriptor_name.into())
                .build()
                .map_err(display_error)
        });
    let first = structures
        .next()
        .ok_or_else(|| "ExtraFileDescriptors must not be empty".to_owned())??;
    if first.signature().to_string() != "(hs)" {
        return Err(format!(
            "ExtraFileDescriptors item signature must be (hs), got {}",
            first.signature()
        ));
    }
    let mut array = ZbusArray::new(first.signature());
    array
        .append(ZbusValue::Structure(first))
        .map_err(display_error)?;
    for structure in structures {
        array
            .append(ZbusValue::Structure(structure?))
            .map_err(display_error)?;
    }
    let value = ZbusValue::Array(array)
        .try_into_owned()
        .map_err(display_error)?;
    Ok((name.to_owned(), value))
}

fn monotonic_ns() -> Result<u64, String> {
    let time = clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(display_error)?;
    let seconds = u64::try_from(time.tv_sec()).map_err(display_error)?;
    let nanoseconds = u64::try_from(time.tv_nsec()).map_err(display_error)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| "monotonic clock overflow".to_owned())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0_u8; N];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(display_error)?;
    Ok(bytes)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(display_error)?
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected {N} decoded bytes"))
}

fn required_argument<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, String> {
    let prefix = format!("{name}=");
    arguments
        .iter()
        .find_map(|argument| argument.strip_prefix(&prefix))
        .ok_or_else(|| format!("missing {name}"))
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
