//! Hosted-only release-barrier proof for ADR-069 revision 19.

use crate::release_wire::{
    decode_launch_parameters, decode_release, encode_launch_parameters, encode_ready,
    fd_layout_digest, launch_parameter_digest, proof_digest, proof_signing_key, ready_digest,
    verify_release_signature, FdIdentity, FdLayout, LaunchParameters, Ready, Release,
};
use nix::{
    fcntl::{fcntl, AtFlags, FcntlArg, FdFlag},
    sys::{
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
    collections::HashSet,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{IoSliceMut, Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::process::ExitStatusExt as _,
    os::{
        fd::{AsRawFd as _, OwnedFd, RawFd},
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::{Component, Path, PathBuf},
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
const RELEASE_WAIT_TIMEOUT_SECS: i64 = 30;

struct DescriptorSet {
    descriptors: Vec<(String, OwnedFd)>,
    retained_peers: Vec<OwnedFd>,
}

struct ImageAuthority {
    root_image: String,
    partition_table: String,
    root_hash: Vec<u8>,
    sim1_digest: [u8; 32],
}

struct MountedImage {
    root: PathBuf,
    root_device: String,
    root_major_minor: String,
    root_filesystem: String,
    activation_digest: [u8; 32],
}

impl Drop for MountedImage {
    fn drop(&mut self) {
        let root = self.root.to_string_lossy().into_owned();
        let _ = Command::new("systemd-dissect")
            .args(["--umount", root.as_str()])
            .status();
        let _ = std::fs::remove_dir(&self.root);
    }
}

struct LaunchRecord {
    parameters: LaunchParameters,
    encoded_hex: String,
}

struct ReleaseConfiguration<'a> {
    mounted_image: &'a MountedImage,
    mode: ExecutionMode,
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
        .any(|argument| argument == "--seccomp-denied-syscall-probe")
    {
        return Some(denied_syscall_probe());
    }
    if arguments
        .iter()
        .any(|argument| argument == "--address-family-denial-probe")
    {
        return Some(address_family_denial_probe());
    }
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
    let mounted_image = mount_verified_image(&image, &launch.parameters.attempt_id)?;
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
        &mounted_image.root,
        &launch.encoded_hex,
        mode,
        proof_case == ProofCase::HigherDescriptor,
        extra_descriptors,
    )?;
    manager
        .start_transient_unit(unit.clone(), "fail".to_owned(), properties, vec![])
        .await
        .map_err(display_error)?;
    let unit_path = manager
        .get_unit(unit.clone())
        .await
        .map_err(display_error)?;
    let service = zbus::Proxy::new(
        &connection,
        "org.freedesktop.systemd1",
        unit_path,
        "org.freedesktop.systemd1.Service",
    )
    .await
    .map_err(display_error)?;

    // Keep the opposite endpoints of deliberately malformed descriptors alive
    // until systemd has consumed the request.
    let _retained_defect_peers = descriptor_set.retained_peers;

    let result = complete_release(
        &manager,
        &service,
        &unit,
        &launch.parameters,
        &channels.provider_release,
        channels.provider_proxy.as_ref(),
        &ReleaseConfiguration {
            mounted_image: &mounted_image,
            mode,
        },
        proof_case,
    )
    .await;
    if result.is_err() {
        emit_unit_diagnostics(&unit);
    }
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
    report_release_result(proof_case, mode, &unit);
    Ok(())
}

fn report_release_result(proof_case: ProofCase, mode: ExecutionMode, unit: &str) {
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
}

fn emit_unit_diagnostics(unit: &str) {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=ActiveState,SubState,Result,MainPID,ExecMainCode,ExecMainStatus",
        ])
        .output();
    match output {
        Ok(output) => eprintln!(
            "release_barrier_unit_diagnostics;{}",
            String::from_utf8_lossy(&output.stdout).replace('\n', ";")
        ),
        Err(error) => eprintln!("release_barrier_unit_diagnostics_error;{error}"),
    }
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
        &TimeVal::seconds(RELEASE_WAIT_TIMEOUT_SECS),
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
    // StartTransientUnit returns before root-image activation and launcher exec
    // complete. Keep that startup budget separate from the launcher's bounded
    // two-second ReleaseV1 wait.
    setsockopt(release, sockopt::ReceiveTimeout, &TimeVal::seconds(30)).map_err(display_error)?;
    if let Some(proxy) = proxy {
        setsockopt(proxy, sockopt::ReceiveTimeout, &TimeVal::seconds(5)).map_err(display_error)?;
    }
    Ok(())
}

fn load_image_authority(arguments: &[String]) -> Result<ImageAuthority, String> {
    let root_image = required_argument(arguments, "--root-image")?;
    let partition_table = required_argument(arguments, "--partition-table")?;
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
        partition_table: partition_table.to_owned(),
        root_hash,
        sim1_digest: digest_file(Path::new(root_image))?,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the linear trust-chain readback is intentionally kept in verification order"
)]
fn mount_verified_image(
    image: &ImageAuthority,
    attempt_id: &[u8; 16],
) -> Result<MountedImage, String> {
    let root = PathBuf::from(format!("/run/pigloros-sim1-{}", hex::encode(attempt_id)));
    std::fs::create_dir(&root).map_err(display_error)?;
    let root_hash = format!("--root-hash={}", hex::encode(&image.root_hash));
    let root_path = root.to_string_lossy().into_owned();
    let output = Command::new("systemd-dissect")
        .args([
            "--mount",
            "--read-only",
            root_hash.as_str(),
            image.root_image.as_str(),
            root_path.as_str(),
        ])
        .output()
        .map_err(display_error)?;
    if !output.status.success() {
        let _ = std::fs::remove_dir(&root);
        return Err(format!(
            "provider dm-verity activation failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut mounted = MountedImage {
        root,
        root_device: String::new(),
        root_major_minor: String::new(),
        root_filesystem: String::new(),
        activation_digest: [0; 32],
    };
    let observed_partition_table = command_output(
        Command::new("sfdisk").args(["--json", image.root_image.as_str()]),
        "read admitted GPT partition table",
    )?;
    let expected_partition_table =
        std::fs::read_to_string(&image.partition_table).map_err(display_error)?;
    if observed_partition_table.trim() != expected_partition_table.trim() {
        return Err("admitted GPT partition identity or offsets changed".to_owned());
    }
    let mount_readback = command_output(
        Command::new("findmnt").args([
            "--raw",
            "--noheadings",
            "--output=SOURCE,FSTYPE,OPTIONS,MAJ:MIN",
            "--target",
            root_path.as_str(),
        ]),
        "read provider image mount",
    )?;
    let mount_fields = mount_readback.split_whitespace().collect::<Vec<_>>();
    if mount_fields.len() != 4
        || !mount_fields[0].starts_with("/dev/mapper/")
        || !mount_fields[2].split(',').any(|option| option == "ro")
    {
        return Err("provider image mount source or flags mismatch".to_owned());
    }
    let root_device = mount_fields[0].to_owned();
    let root_major_minor = mount_fields[3].to_owned();
    let mapper_name = root_device
        .strip_prefix("/dev/mapper/")
        .ok_or_else(|| "provider root is not a device-mapper source".to_owned())?;
    let mapper_table = command_output(
        Command::new("dmsetup").args(["table", "--showkeys", mapper_name]),
        "read exact dm-verity mapping",
    )?;
    let table_fields = mapper_table.split_whitespace().collect::<Vec<_>>();
    let verity_index = table_fields
        .iter()
        .position(|field| *field == "verity")
        .ok_or_else(|| "provider root mapping is not dm-verity".to_owned())?;
    let data_device = table_fields
        .get(verity_index + 2)
        .ok_or_else(|| "dm-verity data device is absent".to_owned())?;
    let hash_device = table_fields
        .get(verity_index + 3)
        .ok_or_else(|| "dm-verity hash device is absent".to_owned())?;
    let expected_root_hash = hex::encode(&image.root_hash);
    if data_device == hash_device
        || !table_fields
            .iter()
            .any(|field| *field == expected_root_hash)
    {
        return Err("exact dm-verity devices or root hash mismatch".to_owned());
    }
    let block_readback = command_output(
        Command::new("lsblk").args([
            "--raw",
            "--noheadings",
            "--output=NAME,MAJ:MIN,PKNAME,START",
        ]),
        "read loop partition identities",
    )?;
    let mut loop_parents = Vec::new();
    for (device, partition_number) in [(data_device, "1"), (hash_device, "2")] {
        let expected_start = command_output(
            Command::new("sfdisk").args([
                "--part-start",
                image.root_image.as_str(),
                partition_number,
            ]),
            "read admitted GPT partition offset",
        )?;
        let parent = block_readback.lines().find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.get(1) == Some(device)
                && fields
                    .get(2)
                    .is_some_and(|parent| parent.starts_with("loop"))
                && fields.get(3) == Some(&expected_start.as_str()))
            .then(|| fields[2].to_owned())
        });
        let Some(parent) = parent else {
            return Err(format!(
                "dm-verity device {device} is not an admitted loop partition"
            ));
        };
        loop_parents.push(parent);
    }
    let loop_readback = command_output(
        Command::new("losetup").args(["--list", "--noheadings", "--output=NAME,BACK-FILE,OFFSET"]),
        "read loop backing identity",
    )?;
    let canonical_image = std::fs::canonicalize(&image.root_image).map_err(display_error)?;
    for parent in loop_parents {
        let expected_loop = format!("/dev/{parent}");
        if !loop_readback.lines().any(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.first() == Some(&expected_loop.as_str())
                && fields.get(1).is_some_and(|backing| {
                    std::fs::canonicalize(backing).is_ok_and(|path| path == canonical_image)
                })
                && fields.get(2).is_some_and(|offset| *offset == "0")
        }) {
            return Err(format!(
                "dm-verity loop {expected_loop} does not reference the admitted image at offset zero"
            ));
        }
    }
    let image_metadata = std::fs::metadata(&canonical_image).map_err(display_error)?;
    let activation_record = format!(
        "image={};digest={};length={};device={};inode={};partition_digest={};mount={mount_readback};mapper={mapper_name};table={mapper_table};blocks={block_readback};loops={loop_readback}",
        canonical_image.display(),
        hex::encode(image.sim1_digest),
        image_metadata.len(),
        image_metadata.dev(),
        image_metadata.ino(),
        hex::encode(digest_file(Path::new(&image.partition_table))?),
    );
    let activation_digest = *blake3::hash(activation_record.as_bytes()).as_bytes();
    mounted.root_device = root_device;
    mounted.root_major_minor = root_major_minor;
    mount_fields[1].clone_into(&mut mounted.root_filesystem);
    mounted.activation_digest = activation_digest;
    println!(
        "provider_image_activation=verified-before-private-ipc;root_hash={};activation_digest={}",
        expected_root_hash,
        hex::encode(activation_digest)
    );
    Ok(mounted)
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
        ProofCase::ExtraDescriptor => {
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
        | ProofCase::ProviderDeathHold
        | ProofCase::HigherDescriptor => {}
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
    root_directory: &Path,
    parameter_hex: &str,
    mode: ExecutionMode,
    inject_higher_descriptor: bool,
    extra_descriptors: Vec<(String, ZbusOwnedFd)>,
) -> Result<Vec<(String, OwnedValue)>, String> {
    let mut launcher_arguments = vec![
        RELEASE_LAUNCHER.to_owned(),
        "--release-launcher".to_owned(),
        format!("--mode={}", mode.name()),
        format!("--launch-parameters={parameter_hex}"),
    ];
    if inject_higher_descriptor {
        launcher_arguments.push("--inject-higher-descriptor".to_owned());
    }
    let bind = vec![(
        executable.display().to_string(),
        RELEASE_LAUNCHER.to_owned(),
        false,
        0_u64,
    )];
    let syscalls = flattened_release_syscalls()?;
    Ok(vec![
        property("Description", "PiglorOS ADR-069 release barrier proof")?,
        property("Type", "exec")?,
        property("StandardOutput", "journal+console")?,
        property("StandardError", "journal+console")?,
        property(
            "ExecStart",
            vec![(RELEASE_LAUNCHER.to_owned(), launcher_arguments, false)],
        )?,
        property("RootDirectory", root_directory.display().to_string())?,
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
    service: &zbus::Proxy<'_>,
    unit: &str,
    parameters: &LaunchParameters,
    release_socket: &OwnedFd,
    proxy_socket: Option<&OwnedFd>,
    configuration: &ReleaseConfiguration<'_>,
    proof_case: ProofCase,
) -> Result<(), String> {
    let (ready_bytes, credential_pid) = receive_ready(release_socket)?;
    let ready = crate::release_wire::decode_ready(&ready_bytes)?;
    let (main_pid, _namespace_descriptors) =
        validate_ready_state(unit, parameters, &ready, credential_pid)?;
    validate_requested_readback(
        service,
        unit,
        parameters,
        configuration.mounted_image,
        configuration.mode,
    )
    .await?;
    let network = configure_network(main_pid, parameters.attempt_id, configuration.mode)?;
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
        thread::sleep(Duration::from_millis(
            RELEASE_WAIT_TIMEOUT_SECS as u64 * 1_000 + 250,
        ));
        return confirm_negative_termination(unit, required_proxy(proxy_socket)?);
    }

    let release_bytes = build_release(
        parameters,
        &ready_bytes,
        &network,
        configuration.mounted_image.activation_digest,
        proof_case,
    )?;
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
    ready: &Ready,
    credential_pid: u32,
) -> Result<(u32, Vec<File>), String> {
    let encoded_parameters = encode_launch_parameters(parameters)?;
    let main_pid = wait_for_main_pid(unit)?;
    if credential_pid != main_pid
        || ready.attempt_id != parameters.attempt_id
        || ready.nonce != parameters.nonce
        || ready.sim1_digest != parameters.sim1_digest
        || ready.launch_parameter_digest != launch_parameter_digest(&encoded_parameters)?
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
    image_activation_digest: [u8; 32],
    proof_case: ProofCase,
) -> Result<Vec<u8>, String> {
    let expected_readback_digest = combined_readback_digest(
        image_activation_digest,
        local_network.expected_readback_digest,
    );
    let observed_readback_digest = combined_readback_digest(
        image_activation_digest,
        local_network.observed_readback_digest,
    );
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
        expected_readback_digest,
        observed_readback_digest,
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

fn combined_readback_digest(image: [u8; 32], network: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros-release-readback-v1\0");
    hasher.update(&image);
    hasher.update(&network);
    *hasher.finalize().as_bytes()
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
    let expected_descriptors = if mode == ExecutionMode::Local {
        vec![
            (3, PROXY_NAME, SockType::Stream),
            (4, RELEASE_NAME, SockType::SeqPacket),
        ]
    } else {
        vec![(3, RELEASE_NAME, SockType::SeqPacket)]
    };
    let higher_descriptor_pair = arguments
        .iter()
        .any(|argument| argument == "--inject-higher-descriptor")
        .then(|| {
            socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            )
            .map_err(display_error)
        })
        .transpose()?;
    if higher_descriptor_pair
        .as_ref()
        .is_some_and(|(first, second)| first.as_raw_fd() <= 4 || second.as_raw_fd() <= 4)
    {
        return Err("higher-descriptor probe did not allocate above FD 4".to_owned());
    }
    let (observed, descriptors) = take_systemd_descriptors(mode.ordinal(), &expected_descriptors)?;
    drop(higher_descriptor_pair);
    if fd_layout_digest(&observed)? != parameters.expected_fd_layout_digest {
        return Err("observed descriptor layout does not match LPV1".to_owned());
    }

    let mut descriptors = descriptors.into_iter();
    let (proxy, release) = if mode == ExecutionMode::Local {
        let proxy = descriptors
            .next()
            .ok_or_else(|| "Local proxy descriptor is absent".to_owned())?;
        let release = descriptors
            .next()
            .ok_or_else(|| "Local release descriptor is absent".to_owned())?;
        (Some(proxy), release)
    } else {
        let release = descriptors
            .next()
            .ok_or_else(|| "release descriptor is absent".to_owned())?;
        (None, release)
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
    prove_effective_kernel_policy()?;
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

fn prove_effective_kernel_policy() -> Result<(), String> {
    let denied_syscall = Command::new(RELEASE_LAUNCHER)
        .arg("--seccomp-denied-syscall-probe")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(display_error)?;
    if !denied_syscall.success() && denied_syscall.signal() != Some(nix::libc::SIGSYS) {
        return Err(format!(
            "forbidden ptrace probe did not observe seccomp denial: {denied_syscall}"
        ));
    }
    let denied_family = Command::new(RELEASE_LAUNCHER)
        .arg("--address-family-denial-probe")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(display_error)?;
    if !denied_family.success() {
        return Err(format!(
            "forbidden AF_INET probe did not observe the configured denial: {denied_family}"
        ));
    }
    println!("kernel_policy_probes=ptrace-denied;af-inet-denied");
    Ok(())
}

fn denied_syscall_probe() -> Result<(), String> {
    match nix::sys::ptrace::traceme() {
        Err(nix::errno::Errno::EPERM) => Ok(()),
        Ok(()) => Err("ptrace unexpectedly passed the effective seccomp filter".to_owned()),
        Err(error) => Err(format!("ptrace probe returned the wrong denial: {error}")),
    }
}

fn address_family_denial_probe() -> Result<(), String> {
    match nix::sys::socket::socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Err(nix::errno::Errno::EAFNOSUPPORT) => Ok(()),
        Ok(_) => Err("AF_INET socket unexpectedly passed the effective filter".to_owned()),
        Err(error) => Err(format!("AF_INET probe returned the wrong denial: {error}")),
    }
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
    if mode == ExecutionMode::Local && descriptors != vec![3] {
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

fn take_systemd_descriptors(
    mode: u8,
    expected: &[(RawFd, &str, SockType)],
) -> Result<(FdLayout, Vec<OwnedFd>), String> {
    let received = sd_listen_fds::get();
    for variable in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(variable);
    }
    let received = received.map_err(display_error)?;
    if received.len() != expected.len() {
        return Err("systemd descriptor count or PID mismatch".to_owned());
    }

    let open = open_non_stdio_descriptors()?;
    if open != expected.iter().map(|(fd, _, _)| *fd).collect::<Vec<_>>() {
        return Err(format!("unexpected inherited descriptors: {open:?}"));
    }
    validate_taken_descriptors(mode, received, expected)
}

fn validate_taken_descriptors(
    mode: u8,
    descriptors: Vec<(Option<String>, sd_listen_fds::OwnedFd)>,
    expected: &[(RawFd, &str, SockType)],
) -> Result<(FdLayout, Vec<OwnedFd>), String> {
    let mut entries = Vec::new();
    let mut owned = Vec::new();
    for ((name, descriptor), &(expected_fd, expected_name, expected_type)) in
        descriptors.into_iter().zip(expected)
    {
        let descriptor = descriptor.into_std();
        if descriptor.as_raw_fd() != expected_fd || name.as_deref() != Some(expected_name) {
            return Err("systemd descriptor names, order, or numbers mismatch".to_owned());
        }
        if socket_type(&descriptor)? != expected_type {
            return Err(format!(
                "descriptor {expected_fd} has the wrong socket type"
            ));
        }
        entries.push((
            u64::try_from(expected_fd).map_err(display_error)?,
            u8::from(expected_type != SockType::Stream),
        ));
        owned.push(descriptor);
    }
    Ok((FdLayout { mode, entries }, owned))
}

fn open_non_stdio_descriptors() -> Result<Vec<RawFd>, String> {
    let entries = std::fs::read_dir("/proc/self/fd").map_err(display_error)?;
    let mut descriptors = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<RawFd>().ok())
        .filter(|descriptor| *descriptor >= 3)
        .collect::<Vec<_>>();
    // Drop the directory iterator before validating the snapshot so its own
    // directory descriptor is not mistaken for inherited process state.
    descriptors.retain(|descriptor| descriptor_is_open(*descriptor));
    descriptors.sort_unstable();
    descriptors.dedup();
    Ok(descriptors)
}

fn descriptor_is_open(descriptor: RawFd) -> bool {
    std::fs::read_link(format!("/proc/self/fd/{descriptor}")).is_ok()
}

fn socket_type(descriptor: &OwnedFd) -> Result<SockType, String> {
    getsockopt(descriptor, sockopt::SockType).map_err(display_error)
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

#[expect(
    clippy::too_many_lines,
    reason = "the complete ADR property matrix stays explicit and auditable"
)]
async fn validate_requested_readback(
    service: &zbus::Proxy<'_>,
    unit: &str,
    parameters: &LaunchParameters,
    mounted_image: &MountedImage,
    mode: ExecutionMode,
) -> Result<(), String> {
    macro_rules! expect_property {
        ($name:literal, $property_type:ty, $expected:expr) => {{
            let expected = $expected;
            let observed: $property_type =
                service.get_property($name).await.map_err(display_error)?;
            if observed != expected {
                return Err(format!(
                    "{} typed readback mismatch: expected {:?}, observed {:?}",
                    $name, expected, observed
                ));
            }
        }};
    }
    expect_property!("Type", String, "exec".to_owned());
    expect_property!("DynamicUser", bool, true);
    expect_property!("NoNewPrivileges", bool, true);
    expect_property!("PrivateDevices", bool, true);
    expect_property!("PrivateIPC", bool, true);
    expect_property!("PrivateMounts", bool, true);
    expect_property!("PrivateNetwork", bool, true);
    expect_property!("PrivatePIDs", String, "yes".to_owned());
    expect_property!("PrivateUsersEx", String, "self".to_owned());
    expect_property!("CapabilityBoundingSet", u64, 0_u64);
    expect_property!("AmbientCapabilities", u64, 0_u64);
    expect_property!("ProtectSystem", String, "strict".to_owned());
    expect_property!("ProtectHome", String, "yes".to_owned());
    expect_property!("ProtectControlGroupsEx", String, "strict".to_owned());
    expect_property!("ProtectKernelTunables", bool, true);
    expect_property!("ProtectKernelModules", bool, true);
    expect_property!("ProtectKernelLogs", bool, true);
    expect_property!("ProtectClock", bool, true);
    expect_property!("ProtectHostname", bool, true);
    expect_property!("ProtectProc", String, "invisible".to_owned());
    expect_property!("ProcSubset", String, "pid".to_owned());
    expect_property!("RestrictNamespaces", u64, 0x7e02_0080_u64);
    expect_property!("RestrictSUIDSGID", bool, true);
    expect_property!("RestrictRealtime", bool, true);
    expect_property!("LockPersonality", bool, true);
    expect_property!(
        "SystemCallArchitectures",
        Vec<String>,
        vec!["native".to_owned()]
    );
    expect_property!(
        "SystemCallFilter",
        (bool, Vec<String>),
        (true, flattened_release_syscalls()?)
    );
    expect_property!(
        "RestrictAddressFamilies",
        (bool, Vec<String>),
        (
            true,
            if mode == ExecutionMode::Local {
                vec!["AF_UNIX".to_owned()]
            } else {
                Vec::<String>::new()
            }
        )
    );
    expect_property!("UMask", u32, 0o77_u32);
    expect_property!("KillMode", String, "control-group".to_owned());
    expect_property!("SendSIGKILL", bool, true);
    expect_property!("FileDescriptorStoreMax", u32, 0_u32);
    expect_property!(
        "ExtraFileDescriptorNames",
        Vec<String>,
        if mode == ExecutionMode::Local {
            vec![PROXY_NAME.to_owned(), RELEASE_NAME.to_owned()]
        } else {
            vec![RELEASE_NAME.to_owned()]
        }
    );
    expect_property!(
        "RootDirectory",
        String,
        mounted_image.root.display().to_string()
    );
    let provider_executable = std::env::current_exe().map_err(display_error)?;
    expect_property!(
        "BindReadOnlyPaths",
        Vec<(String, String, bool, u64)>,
        vec![(
            provider_executable.display().to_string(),
            RELEASE_LAUNCHER.to_owned(),
            false,
            0_u64,
        )]
    );
    if unit_property(unit, "RootDirectory")?.trim() != mounted_image.root.to_string_lossy().as_ref()
    {
        return Err("RootDirectory readback mismatch".to_owned());
    }
    for omitted in [
        "RootImage",
        "RootHash",
        "RootHashSignature",
        "RootImagePolicy",
    ] {
        if !unit_property(unit, omitted)?.trim().is_empty() {
            return Err(format!("{omitted} was delegated to the transient unit"));
        }
    }
    let main_pid = wait_for_main_pid(unit)?;
    let mountinfo =
        std::fs::read_to_string(format!("/proc/{main_pid}/mountinfo")).map_err(display_error)?;
    let root_mount = mountinfo
        .lines()
        .find(|line| line.split_whitespace().nth(4) == Some("/"))
        .ok_or_else(|| "unit root mount is absent".to_owned())?;
    let fields = root_mount.split_whitespace().collect::<Vec<_>>();
    let separator = fields
        .iter()
        .position(|field| *field == "-")
        .ok_or_else(|| "unit root mountinfo separator is absent".to_owned())?;
    if fields.get(2) != Some(&mounted_image.root_major_minor.as_str())
        || fields.get(separator + 1) != Some(&mounted_image.root_filesystem.as_str())
        || !fields
            .get(5)
            .is_some_and(|options| options.split(',').any(|option| option == "ro"))
    {
        return Err("unit root source does not match provider activation".to_owned());
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
    // A transient service can remain in deactivating/stop-sigterm for more
    // than five seconds under hosted nested virtualization. Cancellation is
    // already requested before this observer starts; this budget only waits
    // for systemd's authoritative terminal state.
    for _ in 0..1_500 {
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

fn flattened_release_syscalls() -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut pending = vec!["@system-service".to_owned()];
    let mut visited = HashSet::new();
    while let Some(group) = pending.pop() {
        if !visited.insert(group.clone()) {
            continue;
        }
        let output = Command::new("systemd-analyze")
            .env("SYSTEMD_COLORS", "0")
            .args(["syscall-filter", group.as_str()])
            .output()
            .map_err(display_error)?;
        if !output.status.success() {
            return Err(format!("failed to flatten {group}"));
        }
        for line in String::from_utf8(output.stdout)
            .map_err(display_error)?
            .lines()
            .map(str::trim)
            .map(|line| line.trim_start_matches("\u{1b}[0m"))
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            if line.starts_with('@') {
                if line != group {
                    pending.push(line.to_owned());
                }
            } else if line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                names.push(line.to_owned());
            }
        }
    }
    names.sort_unstable();
    names.dedup();
    // These compatibility aliases are not native syscall names on either
    // supported architecture. systemd otherwise ignores them, which makes the
    // requested allow-list differ from the effective kernel filter.
    names.retain(|name| !matches!(name.as_str(), "fstatat" | "llseek" | "newfstat"));
    for required in [
        "execveat",
        "getsockopt",
        "poll",
        "recvmsg",
        "sendto",
        "socket",
    ] {
        if names
            .binary_search_by(|name| name.as_str().cmp(required))
            .is_err()
        {
            return Err(format!(
                "flattened @system-service omits required syscall {required}"
            ));
        }
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
