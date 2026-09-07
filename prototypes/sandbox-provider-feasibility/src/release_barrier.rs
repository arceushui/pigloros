//! Hosted-only release-barrier proof for ADR-069 revision 19.

use crate::release_wire::{
    decode_launch_parameters, decode_release, encode_launch_parameters, encode_ready,
    fd_layout_digest, launch_parameter_digest, proof_digest, proof_signing_key, ready_digest,
    FdIdentity, FdLayout, LaunchParameters, Ready, Release,
};
use nix::{
    fcntl::{fcntl, AtFlags, FcntlArg, FdFlag},
    sys::{
        resource::{getrlimit, Resource, RLIM_INFINITY},
        socket::{
            getsockopt, recv, recvmsg, send, setsockopt, socketpair, sockopt, AddressFamily,
            ControlMessageOwned, MsgFlags, SockFlag, SockType,
        },
    },
    time::{clock_gettime, ClockId},
    unistd::execveat,
};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{IoSliceMut, Read as _, Seek as _, SeekFrom},
    os::{
        fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt as _,
    },
    path::{Component, Path},
    process::Command,
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
        return Some(run_adapter());
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
    let root_signature = std::fs::read(signature_path).map_err(display_error)?;
    let sim1_digest = digest_file(Path::new(root_image))?;
    let attempt_id = random_bytes()?;
    let nonce = random_bytes()?;
    let expected_layout = FdLayout {
        mode: 0,
        entries: vec![(3, 0), (4, 1)],
    };
    let expected_layout_digest = fd_layout_digest(&expected_layout)?;
    let parameters = LaunchParameters {
        attempt_id,
        nonce,
        sim1_digest,
        adapter_path: ADAPTER_PATH.to_owned(),
        adapter_arguments: vec![ADAPTER_PATH.to_owned(), "--release-adapter".to_owned()],
        expected_fd_layout_digest: expected_layout_digest,
    };
    let encoded_parameters = encode_launch_parameters(&parameters)?;
    let parameter_hex = hex::encode(&encoded_parameters);

    let (provider_proxy, launcher_proxy) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(display_error)?;
    let (provider_release, launcher_release) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(display_error)?;
    setsockopt(&provider_release, sockopt::PassCred, &true).map_err(display_error)?;

    let executable = std::env::current_exe().map_err(display_error)?;
    ensure_static_native_elf(&executable)?;
    let unit = format!("pigloros-release-{}.service", hex::encode(attempt_id));
    let connection = zbus::Connection::system().await.map_err(display_error)?;
    let manager = zbus_systemd::systemd1::ManagerProxy::new(&connection)
        .await
        .map_err(display_error)?;
    let extra_descriptors = vec![
        (PROXY_NAME.to_owned(), ZbusOwnedFd::from(launcher_proxy)),
        (RELEASE_NAME.to_owned(), ZbusOwnedFd::from(launcher_release)),
    ];
    let properties = transient_properties(
        &executable,
        root_image,
        root_hash,
        root_signature,
        &parameter_hex,
        extra_descriptors,
    )?;
    manager
        .start_transient_unit(unit.clone(), "fail".to_owned(), properties, vec![])
        .await
        .map_err(display_error)?;

    let result = complete_release(
        &manager,
        &unit,
        &parameters,
        &encoded_parameters,
        &provider_release,
        &provider_proxy,
    )
    .await;
    let _ = manager.stop_unit(unit.clone(), "replace".to_owned()).await;
    let _ = manager.reset_failed_unit(unit.clone()).await;
    result?;
    println!(
        "release_barrier=typed-local-release-ok;unit={unit};fd3=proxy-only;fd4=closed-before-adapter"
    );
    Ok(())
}

fn transient_properties(
    executable: &Path,
    root_image: &str,
    root_hash: Vec<u8>,
    root_signature: Vec<u8>,
    parameter_hex: &str,
    extra_descriptors: Vec<(String, ZbusOwnedFd)>,
) -> Result<Vec<(String, OwnedValue)>, String> {
    let launcher_arguments = vec![
        RELEASE_LAUNCHER.to_owned(),
        "--release-launcher".to_owned(),
        "--mode=local".to_owned(),
        format!("--launch-parameters={parameter_hex}"),
    ];
    let bind = format!("{}:{RELEASE_LAUNCHER}", executable.display());
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
        property("BindReadOnlyPaths", vec![bind])?,
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
            (true, vec!["AF_UNIX".to_owned()]),
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
    proxy_socket: &OwnedFd,
) -> Result<(), String> {
    let (ready_bytes, credential_pid) = receive_ready(release_socket)?;
    let ready = crate::release_wire::decode_ready(&ready_bytes)?;
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
    validate_ready_executables(main_pid, &ready)?;
    validate_namespaces(main_pid)?;
    validate_requested_readback(unit, parameters)?;
    let mut premature_marker = [0_u8; 64];
    match recv(
        proxy_socket.as_raw_fd(),
        &mut premature_marker,
        MsgFlags::MSG_DONTWAIT,
    ) {
        Err(nix::errno::Errno::EAGAIN) => {}
        Ok(0) => return Err("Local proxy closed before release".to_owned()),
        Ok(_) => return Err("adapter executed before ReleaseV1".to_owned()),
        Err(error) => return Err(format!("Local proxy pre-release probe failed: {error}")),
    }

    let ready_digest = ready_digest(&ready_bytes)?;
    let observed = proof_digest("release-proof-observed-readback-v1");
    let release = Release {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        ready_digest,
        trs1_digest: proof_digest("TRS1-proof"),
        rvs1_digest: proof_digest("RVS1-proof"),
        apt1_digest: proof_digest("APT1-proof"),
        trust_epoch: 7,
        revocation_epoch: 11,
        policy_epoch: 13,
        expected_readback_digest: observed,
        observed_readback_digest: observed,
        deadline_monotonic_ns: monotonic_ns()?.saturating_add(5_000_000_000),
        runtime_key_id: "adr069-proof-runtime-key".to_owned(),
    };
    let release_bytes = crate::release_wire::encode_release(&release, &proof_signing_key())?;
    send_packet(release_socket.as_raw_fd(), &release_bytes)?;

    let mut marker = [0_u8; 64];
    let count =
        recv(proxy_socket.as_raw_fd(), &mut marker, MsgFlags::empty()).map_err(display_error)?;
    if &marker[..count] != b"ADAPTER_EXECUTED_FD3" {
        return Err("adapter did not retain exactly the Local proxy on FD 3".to_owned());
    }
    wait_for_unit_terminal(manager, unit).await
}

fn run_launcher(arguments: &[String]) -> Result<(), String> {
    if required_argument(arguments, "--mode")? != "local" {
        return Err("proof launcher accepts only Local mode".to_owned());
    }
    let encoded =
        hex::decode(required_argument(arguments, "--launch-parameters")?).map_err(display_error)?;
    let parameters = decode_launch_parameters(&encoded)?;
    validate_systemd_descriptor_environment(&[(3, PROXY_NAME), (4, RELEASE_NAME)])?;
    let observed = observed_layout(0, &[(3, SockType::Stream), (4, SockType::SeqPacket)])?;
    if fd_layout_digest(&observed)? != parameters.expected_fd_layout_digest {
        return Err("observed descriptor layout does not match LPV1".to_owned());
    }

    let proxy = take_inherited_fd(3)?;
    let release = take_inherited_fd(4)?;
    let provider_credentials =
        getsockopt(&release, sockopt::PeerCredentials).map_err(display_error)?;
    if provider_credentials.uid() != 0 {
        return Err("release peer is not the root provider".to_owned());
    }
    set_close_on_exec(&proxy, true)?;
    set_close_on_exec(&release, true)?;
    let adapter = open_native_adapter(&parameters.adapter_path)?;
    let ready = build_ready(&parameters, &encoded, &adapter, &observed)?;
    let ready_bytes = encode_ready(&ready)?;
    send_packet(release.as_raw_fd(), &ready_bytes)?;

    let release_bytes = receive_packet(release.as_raw_fd())?;
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
    set_close_on_exec(&proxy, false)?;
    exec_adapter(adapter, &parameters.adapter_arguments)
}

fn run_adapter() -> Result<(), String> {
    if std::env::vars_os().next().is_some() {
        return Err("adapter environment was not empty".to_owned());
    }
    let descriptors = open_non_stdio_descriptors()?;
    if descriptors != vec![3] || socket_type(3)? != SockType::Stream {
        return Err(format!(
            "adapter descriptor set is not exactly FD 3: {descriptors:?}"
        ));
    }
    if send(3, b"ADAPTER_EXECUTED_FD3", MsgFlags::empty()).map_err(display_error)? != 20 {
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
            if expected_type == SockType::Stream {
                0
            } else {
                1
            },
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

fn exec_adapter(adapter: File, arguments: &[String]) -> Result<(), String> {
    let arguments = arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()).map_err(display_error))
        .collect::<Result<Vec<_>, _>>()?;
    let empty_path = CString::new("").map_err(display_error)?;
    let empty_environment: Vec<CString> = Vec::new();
    execveat(
        &adapter,
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
    let mut iov = [IoSliceMut::new(&mut bytes)];
    let mut control = nix::cmsg_space!(nix::sys::socket::UnixCredentials);
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
    let count = message.bytes;
    drop(message);
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
    use std::os::unix::fs::MetadataExt as _;
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

fn validate_namespaces(main_pid: u32) -> Result<(), String> {
    for namespace in ["mnt", "pid", "ipc", "uts", "user", "net"] {
        let provider =
            std::fs::read_link(format!("/proc/self/ns/{namespace}")).map_err(display_error)?;
        let launcher = std::fs::read_link(format!("/proc/{main_pid}/ns/{namespace}"))
            .map_err(display_error)?;
        if provider == launcher {
            return Err(format!("{namespace} namespace was not isolated"));
        }
    }
    Ok(())
}

fn validate_ready_executables(main_pid: u32, ready: &Ready) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

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

fn validate_requested_readback(unit: &str, parameters: &LaunchParameters) -> Result<(), String> {
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
    for _ in 0..100 {
        let active = unit_property(unit, "ActiveState")?;
        if matches!(active.trim(), "inactive" | "failed") {
            let status = unit_property(unit, "ExecMainStatus")?;
            if status.trim() == "0" {
                return Ok(());
            }
            return Err(format!("adapter exited with status {}", status.trim()));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = manager
        .stop_unit(unit.to_owned(), "replace".to_owned())
        .await;
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
            StructureBuilder::new()
                .add_field(descriptor_name)
                .append_field(ZbusValue::Fd(descriptor.into()))
                .build()
                .map_err(display_error)
        });
    let first = structures
        .next()
        .ok_or_else(|| "ExtraFileDescriptors must not be empty".to_owned())??;
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
