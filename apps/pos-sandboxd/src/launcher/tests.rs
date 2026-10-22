use std::{
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::symlink,
    },
    sync::Mutex,
    thread,
};

use pos_reference::sandbox_provider_protocol::{
    blake3_digest_of, fdl1_digest, ExecutionRelease, ExecutionReleaseFields, FdLayoutEntry, FdRole,
    LaunchParameters, LauncherReady, SandboxExecutionMode,
};
use rustix::{
    net::{
        recvmsg, send, sendmsg, socketpair, AddressFamily, RecvAncillaryBuffer,
        RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
        SocketFlags, SocketType, UCred,
    },
    process::{getgid, getpid, getuid},
};

use super::{
    adapter::{hold, hold_adapter, open_beneath, ELF_HEADER_BYTES, NATIVE_MACHINE},
    barrier::{receive_release, run, send_ready},
    decode_hex, decode_parameters,
    descriptors::{scan_proc_self_fd, validate, Inherited, HOST_SERVICE_NAME, RELEASE_NAME},
    environment::LaunchEnvironment,
    error::{LauncherError, ReleaseDefect},
    host::{LaunchHost, ProcessHost},
};

type TestResult = Result<(), Box<dyn Error>>;

const ATTEMPT: [u8; 16] = [7; 16];
const NONCE: [u8; 32] = [9; 32];
const SIM1: [u8; 32] = [3; 32];

fn pair(kind: SocketType) -> Result<(OwnedFd, OwnedFd), Box<dyn Error>> {
    Ok(socketpair(
        AddressFamily::UNIX,
        kind,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

fn release_layout() -> [FdLayoutEntry; 1] {
    [FdLayoutEntry {
        fd_number: 3,
        role: FdRole::Release,
    }]
}

fn local_layout() -> [FdLayoutEntry; 2] {
    [
        FdLayoutEntry {
            fd_number: 3,
            role: FdRole::HostService,
        },
        FdLayoutEntry {
            fd_number: 4,
            role: FdRole::Release,
        },
    ]
}

fn elf_header(machine: u16) -> Vec<u8> {
    let mut header = vec![0_u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[16..18].copy_from_slice(&2_u16.to_le_bytes());
    header[18..20].copy_from_slice(&machine.to_le_bytes());
    header
}

fn parameters(arguments: Vec<String>) -> Result<LaunchParameters, Box<dyn Error>> {
    Ok(LaunchParameters::new(
        ATTEMPT,
        NONCE,
        SIM1,
        "/adapter".to_owned(),
        arguments,
        fdl1_digest(SandboxExecutionMode::AirGapped, &release_layout())?,
    )?)
}

fn environment() -> LaunchEnvironment {
    LaunchEnvironment {
        launch_instance_id: [5; 16],
        descriptor_count: 1,
    }
}

struct TestHost {
    root: File,
    launcher: File,
    launcher_missing: bool,
    provider_uid: u32,
    open: io::Result<Vec<u32>>,
    now: io::Result<u64>,
    executions: Mutex<Vec<Vec<CString>>>,
    /// Descriptor whose close-on-exec flag is read when the exec is reached.
    inspect: Option<i32>,
    inspected_cloexec: Mutex<Option<bool>>,
}

impl TestHost {
    fn new(
        directory: &tempfile::TempDir,
        release: &OwnedFd,
        adapter: &[u8],
    ) -> Result<Self, Box<dyn Error>> {
        fs::write(directory.path().join("adapter"), adapter)?;
        fs::write(directory.path().join("launcher"), b"launcher image")?;
        Ok(Self {
            root: File::open(directory.path())?,
            launcher: File::open(directory.path().join("launcher"))?,
            launcher_missing: false,
            provider_uid: getuid().as_raw(),
            open: Ok(vec![u32::try_from(release.as_raw_fd())?]),
            now: Ok(1_000),
            executions: Mutex::new(Vec::new()),
            inspect: None,
            inspected_cloexec: Mutex::new(None),
        })
    }
}

impl LaunchHost for TestHost {
    fn provider_uid(&self) -> u32 {
        self.provider_uid
    }

    fn open_descriptors(&self) -> io::Result<Vec<u32>> {
        self.open
            .as_ref()
            .map(Clone::clone)
            .map_err(|error| io::Error::from(error.kind()))
    }

    fn open_launcher(&self) -> io::Result<File> {
        if self.launcher_missing {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        self.launcher.try_clone()
    }

    fn open_adapter(&self, path: &str) -> io::Result<File> {
        open_beneath(&self.root, path)
    }

    fn monotonic_ns(&self) -> io::Result<u64> {
        self.now
            .as_ref()
            .map(|now| *now)
            .map_err(|error| io::Error::from(error.kind()))
    }

    fn replace_process(&self, _adapter: &File, argv: &[CString]) -> io::Error {
        if let Ok(mut executions) = self.executions.lock() {
            executions.push(argv.to_vec());
        }
        if let (Some(number), Ok(mut seen)) = (self.inspect, self.inspected_cloexec.lock()) {
            // `fdinfo` flags show O_CLOEXEC (02000000) exactly when FD_CLOEXEC is set.
            *seen = fs::read_to_string(format!("/proc/self/fdinfo/{number}"))
                .ok()
                .and_then(|text| {
                    text.lines()
                        .find_map(|line| line.strip_prefix("flags:"))
                        .and_then(|flags| u32::from_str_radix(flags.trim(), 8).ok())
                })
                .map(|flags| flags & 0o200_0000 != 0);
        }
        io::Error::from(io::ErrorKind::Unsupported)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

fn named(name: &str, descriptor: OwnedFd) -> (Option<String>, OwnedFd) {
    (Some(name.to_owned()), descriptor)
}

fn number(descriptor: &OwnedFd) -> Result<u32, Box<dyn Error>> {
    Ok(u32::try_from(descriptor.as_raw_fd())?)
}

#[test]
fn hex_decoding_is_strict_lowercase() {
    assert_eq!(decode_hex("00ff7a"), Some(vec![0, 255, 122]));
    assert_eq!(decode_hex(""), Some(Vec::new()));
    for rejected in ["0", "0G", "0A", "ab cd", "é"] {
        assert_eq!(decode_hex(rejected), None, "{rejected}");
    }
    assert!(matches!(
        decode_parameters("zz"),
        Err(LauncherError::Parameters)
    ));
    assert!(matches!(
        decode_parameters("00"),
        Err(LauncherError::Parameters)
    ));
}

#[test]
fn parameters_decode_from_their_canonical_hex() -> TestResult {
    let expected = parameters(vec!["--serve".to_owned()])?;
    let hex = hex(&expected.to_canonical_cbor()?);
    assert_eq!(decode_parameters(&hex)?, expected);
    Ok(())
}

fn variables(name: &str) -> Option<String> {
    match name {
        "LISTEN_PID" => Some("42".to_owned()),
        "LISTEN_FDS" => Some("2".to_owned()),
        "INVOCATION_ID" => Some("0123456789abcdef0123456789abcdef".to_owned()),
        _ => None,
    }
}

#[test]
fn environment_accepts_only_this_process_with_one_or_two_descriptors() {
    let read = |lookup: &dyn Fn(&str) -> Option<String>, pid| LaunchEnvironment::read(lookup, pid);
    let ok = read(&variables, 42);
    assert_eq!(
        ok.as_ref().map(|value| value.descriptor_count).ok(),
        Some(2)
    );
    assert_eq!(
        ok.map(|value| value.launch_instance_id).ok(),
        Some([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef
        ])
    );
    assert!(read(&variables, 43).is_err());
    for (variable, value) in [
        ("LISTEN_PID", "x"),
        ("LISTEN_FDS", "0"),
        ("LISTEN_FDS", "3"),
        ("LISTEN_FDS", "-1"),
        ("INVOCATION_ID", "0123456789abcdef0123456789abcde"),
        ("INVOCATION_ID", "0123456789ABCDEF0123456789abcdef"),
        ("INVOCATION_ID", "0123456789abcdef0123456789abcdeg"),
        ("INVOCATION_ID", "00000000000000000000000000000000"),
    ] {
        let overridden = |name: &str| {
            if name == variable {
                Some(value.to_owned())
            } else {
                variables(name)
            }
        };
        assert!(
            matches!(read(&overridden, 42), Err(LauncherError::Environment)),
            "{variable}={value}"
        );
        let missing = |name: &str| (name != variable).then(|| variables(name)).flatten();
        assert!(read(&missing, 42).is_err(), "missing {variable}");
    }
}

#[test]
fn the_process_environment_of_a_test_is_not_a_launch_environment() {
    assert!(matches!(
        LaunchEnvironment::from_process(),
        Err(LauncherError::Environment)
    ));
}

#[test]
fn validation_accepts_the_release_only_and_local_layouts_and_seals_them() -> TestResult {
    let (provider, release) = socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::empty(),
        None,
    )?;
    drop(provider);
    let open = vec![number(&release)?];
    let layout = validate(vec![named(RELEASE_NAME, release)], &open)?;
    assert_eq!(layout.entries, release_layout());
    assert!(layout.host_service.is_none());
    assert!(rustix::io::fcntl_getfd(&layout.release)?.contains(rustix::io::FdFlags::CLOEXEC));

    let (_peer, proxy) = pair(SocketType::STREAM)?;
    let (_provider, release) = pair(SocketType::SEQPACKET)?;
    let mut open = vec![number(&proxy)?, number(&release)?];
    open.sort_unstable();
    let layout = validate(
        vec![
            named(HOST_SERVICE_NAME, proxy),
            named(RELEASE_NAME, release),
        ],
        &open,
    )?;
    assert_eq!(layout.entries, local_layout());
    assert!(layout.host_service.is_some());
    Ok(())
}

type Entry<'a> = (Option<&'a str>, &'a OwnedFd);

fn layout_of(
    entries: &[Entry<'_>],
    adjust: impl FnOnce(&mut Vec<u32>),
) -> Result<bool, Box<dyn Error>> {
    let inherited: Inherited = entries
        .iter()
        .map(|(name, descriptor)| Ok((name.map(str::to_owned), descriptor.try_clone()?)))
        .collect::<io::Result<_>>()?;
    let mut open: Vec<u32> = inherited
        .iter()
        .map(|(_, descriptor)| number(descriptor))
        .collect::<Result<_, _>>()?;
    open.sort_unstable();
    adjust(&mut open);
    Ok(matches!(
        validate(inherited, &open),
        Err(LauncherError::Layout)
    ))
}

fn rejected(entries: &[Entry<'_>]) -> Result<bool, Box<dyn Error>> {
    layout_of(entries, |_| {})
}

#[test]
fn validation_rejects_every_layout_defect() -> TestResult {
    let (_p1, release) = pair(SocketType::SEQPACKET)?;
    let (_p2, other) = pair(SocketType::SEQPACKET)?;
    let (_p3, stream) = pair(SocketType::STREAM)?;
    let udp = OwnedFd::from(std::net::UdpSocket::bind("127.0.0.1:0")?);
    let file = OwnedFd::from(File::open("/")?);
    let good = [(Some(RELEASE_NAME), &release)];
    // The control case: the same helper accepts a correct layout.
    assert!(!rejected(&good)?);

    // Names: missing, wrong, reordered, extra, empty.
    assert!(rejected(&[(None, &release)])?);
    assert!(rejected(&[(Some("piglor-other-v1"), &release)])?);
    assert!(rejected(&[])?);
    assert!(rejected(&[
        (Some(RELEASE_NAME), &release),
        (Some(HOST_SERVICE_NAME), &stream)
    ])?);
    assert!(rejected(&[
        (Some(HOST_SERVICE_NAME), &stream),
        (Some(RELEASE_NAME), &release),
        (Some(RELEASE_NAME), &other)
    ])?);
    // Inventory: a higher open descriptor, or a missing one.
    assert!(layout_of(&good, |open| open.push(4_000))?);
    assert!(layout_of(&good, Vec::clear)?);
    // Types: a stream as release, a seqpacket as proxy, a non-UNIX socket, a
    // descriptor that is not a socket.
    assert!(rejected(&[(Some(RELEASE_NAME), &stream)])?);
    assert!(rejected(&[(Some(RELEASE_NAME), &udp)])?);
    assert!(rejected(&[
        (Some(HOST_SERVICE_NAME), &other),
        (Some(RELEASE_NAME), &release)
    ])?);
    assert!(rejected(&[(Some(RELEASE_NAME), &file)])?);
    Ok(())
}

#[test]
fn proc_self_fd_scan_lists_open_descriptors_without_its_own_or_stdio() -> TestResult {
    let file = File::open("/")?;
    let listed = scan_proc_self_fd()?;
    assert!(listed.contains(&u32::try_from(file.as_raw_fd())?));
    assert!(listed.iter().all(|descriptor| *descriptor >= 3));
    assert!(listed.windows(2).all(|pair| pair[0] < pair[1]));
    // The listing descriptor is closed again, so a second scan is identical
    // apart from descriptors other tests open and close concurrently.
    drop(file);
    assert!(scan_proc_self_fd().is_ok());
    Ok(())
}

fn directory_with(name: &str, bytes: &[u8]) -> Result<(tempfile::TempDir, File), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join(name), bytes)?;
    let file = open_beneath(File::open(directory.path())?, name)?;
    Ok((directory, file))
}

#[test]
fn open_beneath_refuses_symlinks_and_escapes() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("real"), b"x")?;
    symlink("real", directory.path().join("link"))?;
    let root = File::open(directory.path())?;
    assert!(open_beneath(&root, "/real").is_ok());
    assert!(open_beneath(&root, "link").is_err());
    assert!(open_beneath(&root, "../escape").is_err());
    assert!(open_beneath(&root, "missing").is_err());
    Ok(())
}

#[test]
fn hold_adapter_accepts_a_native_elf_and_binds_its_digest_and_identity() -> TestResult {
    let bytes = elf_header(NATIVE_MACHINE);
    let (_directory, file) = directory_with("adapter", &bytes)?;
    let held = hold_adapter(file)?;
    assert_eq!(held.digest, blake3_digest_of(&bytes[..])?);
    assert_ne!(held.identity.inode, 0);
    let again = hold(held.file.try_clone()?)?;
    assert_eq!(again.identity, held.identity);
    Ok(())
}

#[test]
fn hold_adapter_rejects_everything_but_a_regular_native_64_bit_le_elf() -> TestResult {
    let mutate = |index: usize, value: u8| {
        let mut bytes = elf_header(NATIVE_MACHINE);
        bytes[index] = value;
        bytes
    };
    let mut cases = vec![
        b"#!/bin/sh\nexit 0\n".to_vec(),
        [b"#!/bin/sh\n".to_vec(), vec![0; 64]].concat(),
        Vec::new(),
        elf_header(NATIVE_MACHINE)[..ELF_HEADER_BYTES - 1].to_vec(),
        elf_header(NATIVE_MACHINE ^ 0x7f),
        mutate(0, 0),
        mutate(4, 1),
        mutate(5, 2),
        mutate(16, 1),
        mutate(16, 4),
    ];
    cases.push(mutate(17, 1));
    for bytes in cases {
        let (_directory, file) = directory_with("adapter", &bytes)?;
        assert!(
            matches!(hold_adapter(file), Err(LauncherError::Adapter)),
            "{bytes:?}"
        );
    }
    let dynamic = {
        let mut bytes = elf_header(NATIVE_MACHINE);
        bytes[16] = 3;
        bytes
    };
    let (_directory, file) = directory_with("adapter", &dynamic)?;
    assert!(hold_adapter(file).is_ok());
    let directory = File::open("/")?;
    assert!(matches!(
        hold_adapter(directory),
        Err(LauncherError::Adapter)
    ));
    Ok(())
}

#[test]
fn hold_rejects_a_descriptor_that_cannot_be_read() -> TestResult {
    let unreadable = fs::OpenOptions::new().write(true).open("/dev/null")?;
    assert!(matches!(hold(unreadable), Err(LauncherError::Identity)));
    Ok(())
}

/// A provider for one launch: it reads the launcher's `ReadyV1` and then sends
/// each datagram it is given.
struct Launch {
    error: LauncherError,
    ready: Option<LauncherReady>,
    credentials: Option<UCred>,
    executions: Vec<Vec<CString>>,
}

fn launch(
    configure: impl FnOnce(&mut TestHost),
    adapter: &[u8],
    arguments: Vec<String>,
    respond: impl FnOnce(&OwnedFd, &LauncherReady) -> TestResult,
) -> Result<Launch, Box<dyn Error>> {
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    let directory = tempfile::tempdir()?;
    let mut host = TestHost::new(&directory, &release, adapter)?;
    configure(&mut host);
    let parameters = parameters(arguments)?;
    let inherited = vec![named(RELEASE_NAME, release)];
    let worker = thread::spawn(move || {
        let result = run(&host, &environment(), &parameters, inherited).err();
        (result, host)
    });
    let received = read_ready(&provider);
    let (ready, credentials) = match received {
        Some((ready, credentials)) => {
            respond(&provider, &ready)?;
            (Some(ready), Some(credentials))
        }
        None => (None, None),
    };
    drop(provider);
    let (error, host) = worker.join().map_err(|_| "launcher thread panicked")?;
    let executions = host.executions.lock().map_err(|_| "poisoned")?.clone();
    Ok(Launch {
        error: error.ok_or("the launcher returned success")?,
        ready,
        credentials,
        executions,
    })
}

fn read_ready(provider: &OwnedFd) -> Option<(LauncherReady, UCred)> {
    rustix::net::sockopt::set_socket_passcred(provider, true).ok()?;
    let mut buffer = [0_u8; 4096];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = recvmsg(
        provider,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut control,
        RecvFlags::empty(),
    )
    .ok()?;
    let credentials = control.drain().find_map(|message| match message {
        RecvAncillaryMessage::ScmCredentials(credentials) => Some(credentials),
        _ => None,
    })?;
    LauncherReady::from_canonical_cbor(&buffer[..received.bytes])
        .ok()
        .map(|ready| (ready, credentials))
}

fn release_fields(ready: &LauncherReady) -> ExecutionReleaseFields {
    ExecutionReleaseFields {
        attempt_id: ATTEMPT,
        nonce: NONCE,
        ready1_digest: ready.digest,
        trs1_digest: [1; 32],
        rvs1_digest: [2; 32],
        apt1_digest: [3; 32],
        trust_epoch: 1,
        revocation_epoch: 2,
        policy_epoch: 3,
        expected_readback_digest: [4; 32],
        observed_readback_digest: [4; 32],
        deadline_monotonic_ns: 5_000,
        runtime_attestation_key_id: "runtime-key".to_owned(),
    }
}

fn signed(fields: ExecutionReleaseFields) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(ExecutionRelease::sign(fields, |_| [1; 64])?.to_canonical_cbor()?)
}

fn release_with(
    change: impl FnOnce(&mut ExecutionReleaseFields),
    ready: &LauncherReady,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut fields = release_fields(ready);
    change(&mut fields);
    signed(fields)
}

fn deliver(provider: &OwnedFd, datagram: &[u8]) -> TestResult {
    assert_eq!(
        send(provider, datagram, SendFlags::NOSIGNAL)?,
        datagram.len()
    );
    Ok(())
}

fn elf() -> Vec<u8> {
    elf_header(NATIVE_MACHINE)
}

#[test]
fn a_valid_release_replaces_the_process_with_the_adapter_and_its_arguments() -> TestResult {
    let outcome = launch(
        |_| {},
        &elf(),
        vec!["--serve".to_owned(), "x".to_owned()],
        |provider, ready| deliver(provider, &release_with(|_| {}, ready)?),
    )?;
    assert!(matches!(outcome.error, LauncherError::Exec(_)));
    assert_eq!(
        outcome.executions,
        vec![vec![
            CString::new("/adapter")?,
            CString::new("--serve")?,
            CString::new("x")?
        ]]
    );
    let ready = outcome.ready.ok_or("no ReadyV1")?;
    let fields = ready.fields;
    assert_eq!(fields.attempt_id, ATTEMPT);
    assert_eq!(fields.nonce, NONCE);
    assert_eq!(fields.launch_instance_id, [5; 16]);
    assert_eq!(fields.sim1_digest, SIM1);
    assert_eq!(fields.adapter_digest, blake3_digest_of(&elf()[..])?);
    assert_eq!(
        fields.launcher_digest,
        blake3_digest_of(&b"launcher image"[..])?
    );
    assert_eq!(fields.expected_fdl1_digest, fields.observed_fdl1_digest);
    assert_eq!(
        fields.launch_parameter_digest,
        parameters(vec!["--serve".to_owned(), "x".to_owned()])?.digest
    );
    let credentials = outcome.credentials.ok_or("no credentials")?;
    assert_eq!(credentials.pid, getpid());
    assert_eq!(credentials.uid, getuid());
    assert_eq!(credentials.gid, getgid());
    Ok(())
}

type DefectCase = (
    &'static str,
    ReleaseDefect,
    Box<dyn Fn(&mut ExecutionReleaseFields)>,
);

fn release_error(
    respond: impl FnOnce(&OwnedFd, &LauncherReady) -> TestResult,
) -> Result<LauncherError, Box<dyn Error>> {
    let outcome = launch(|_| {}, &elf(), Vec::new(), respond)?;
    assert!(outcome.executions.is_empty());
    Ok(outcome.error)
}

#[test]
fn every_release_defect_executes_nothing() -> TestResult {
    let cases: Vec<DefectCase> = vec![
        (
            "attempt",
            ReleaseDefect::Attempt,
            Box::new(|f| f.attempt_id = [8; 16]),
        ),
        (
            "nonce",
            ReleaseDefect::Nonce,
            Box::new(|f| f.nonce = [8; 32]),
        ),
        (
            "ready digest",
            ReleaseDefect::ReadyDigest,
            Box::new(|f| f.ready1_digest = [8; 32]),
        ),
        (
            "expired",
            ReleaseDefect::Expired,
            Box::new(|f| f.deadline_monotonic_ns = 1_000),
        ),
    ];
    for (label, defect, change) in cases {
        let error =
            release_error(|provider, ready| deliver(provider, &release_with(change, ready)?))?;
        assert!(
            matches!(error, LauncherError::Release(found) if found == defect),
            "{label}: {error:?}"
        );
    }
    Ok(())
}

#[test]
fn malformed_oversized_truncated_and_duplicate_releases_execute_nothing() -> TestResult {
    let malformed = release_error(|provider, _| deliver(provider, b"not cbor"))?;
    assert!(matches!(
        malformed,
        LauncherError::Release(ReleaseDefect::Malformed)
    ));
    let oversized = release_error(|provider, _| deliver(provider, &[0_u8; 5000]))?;
    assert!(matches!(
        oversized,
        LauncherError::Release(ReleaseDefect::Malformed)
    ));
    let eof = release_error(|_, _| Ok(()))?;
    assert!(matches!(eof, LauncherError::ReleaseUnavailable));
    let empty = release_error(|provider, _| deliver(provider, b""))?;
    assert!(matches!(empty, LauncherError::ReleaseUnavailable));
    Ok(())
}

#[test]
fn a_release_carrying_a_descriptor_is_rejected() -> TestResult {
    let error = release_error(|provider, ready| {
        let bytes = release_with(|_| {}, ready)?;
        let directory = File::open("/")?;
        let borrowed = [std::os::fd::AsFd::as_fd(&directory)];
        let mut buffer = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut buffer);
        assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
        sendmsg(
            provider,
            &[IoSlice::new(&bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        )?;
        Ok(())
    })?;
    assert!(matches!(
        error,
        LauncherError::Release(ReleaseDefect::Malformed)
    ));
    Ok(())
}

#[test]
fn a_launch_that_cannot_prove_itself_never_sends_ready() -> TestResult {
    let not_root = launch(
        |host| host.provider_uid = host.provider_uid.wrapping_add(1),
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(not_root.error, LauncherError::Peer));
    assert!(not_root.ready.is_none());

    let script = launch(|_| {}, b"#!/bin/sh\n", Vec::new(), |_, _| Ok(()))?;
    assert!(matches!(script.error, LauncherError::Adapter));
    assert!(script.ready.is_none());

    let no_listing = launch(
        |host| host.open = Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(no_listing.error, LauncherError::Layout));

    let extra = launch(
        |host| {
            if let Ok(open) = host.open.as_mut() {
                open.push(4_000);
            }
        },
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(extra.error, LauncherError::Layout));
    assert!(extra.ready.is_none());

    let no_adapter = launch(
        |host| {
            if let Ok(root) = File::open("/proc") {
                host.root = root;
            }
        },
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(no_adapter.error, LauncherError::Adapter));
    Ok(())
}

#[test]
fn a_launcher_image_that_cannot_be_read_never_sends_ready() -> TestResult {
    let outcome = launch(
        |host| {
            if let Ok(unreadable) = fs::OpenOptions::new().write(true).open("/dev/null") {
                host.launcher = unreadable;
            }
        },
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(outcome.error, LauncherError::Identity));
    assert!(outcome.ready.is_none());
    Ok(())
}

#[test]
fn a_missing_launcher_image_never_sends_ready() -> TestResult {
    let outcome = launch(
        |host| host.launcher_missing = true,
        &elf(),
        Vec::new(),
        |_, _| Ok(()),
    )?;
    assert!(matches!(outcome.error, LauncherError::Identity));
    assert!(outcome.ready.is_none());
    Ok(())
}

#[test]
fn a_ready_that_cannot_be_built_or_sent_ends_the_launch() -> TestResult {
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    let directory = tempfile::tempdir()?;
    let host = TestHost::new(&directory, &release, &elf())?;
    let mut zero_nonce = parameters(Vec::new())?;
    zero_nonce.nonce = [0; 32];
    let error = run(
        &host,
        &environment(),
        &zero_nonce,
        vec![named(RELEASE_NAME, release)],
    )
    .err();
    assert!(matches!(error, Some(LauncherError::Ready)));
    drop(provider);

    let (provider, release) = pair(SocketType::SEQPACKET)?;
    drop(provider);
    assert!(matches!(
        send_ready(&release, b"ready"),
        Err(LauncherError::Ready)
    ));
    Ok(())
}

#[test]
fn a_layout_that_matches_no_mode_digest_never_sends_ready() -> TestResult {
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    let directory = tempfile::tempdir()?;
    let host = TestHost::new(&directory, &release, &elf())?;
    let mut wrong = parameters(Vec::new())?;
    wrong.expected_fdl1_digest = [0xee; 32];
    let error = run(
        &host,
        &environment(),
        &wrong,
        vec![named(RELEASE_NAME, release)],
    )
    .err();
    assert!(matches!(error, Some(LauncherError::Layout)));
    drop(provider);
    Ok(())
}

#[test]
fn a_clock_failure_after_release_is_not_a_release() -> TestResult {
    let outcome = launch(
        |host| host.now = Err(io::Error::from(io::ErrorKind::Other)),
        &elf(),
        Vec::new(),
        |provider, ready| deliver(provider, &release_with(|_| {}, ready)?),
    )?;
    assert!(matches!(outcome.error, LauncherError::ReleaseUnavailable));
    assert!(outcome.executions.is_empty());
    Ok(())
}

#[test]
fn an_argument_with_a_nul_byte_is_rejected_before_exec() -> TestResult {
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    let directory = tempfile::tempdir()?;
    let host = TestHost::new(&directory, &release, &elf())?;
    let mut bad = parameters(vec!["a".to_owned()])?;
    bad.arguments = vec!["a\0b".to_owned()];
    let inherited = vec![named(RELEASE_NAME, release)];
    let worker = thread::spawn(move || run(&host, &environment(), &bad, inherited).err());
    let (ready, _) = read_ready(&provider).ok_or("no ReadyV1")?;
    deliver(&provider, &release_with(|_| {}, &ready)?)?;
    let error = worker.join().map_err(|_| "panicked")?;
    assert!(matches!(error, Some(LauncherError::Parameters)));
    Ok(())
}

#[test]
fn the_local_layout_keeps_the_proxy_open_for_the_adapter() -> TestResult {
    let (_proxy_peer, proxy) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    let directory = tempfile::tempdir()?;
    let mut host = TestHost::new(&directory, &release, &elf())?;
    let mut open = vec![number(&proxy)?, number(&release)?];
    open.sort_unstable();
    host.open = Ok(open);
    host.inspect = Some(proxy.as_raw_fd());
    let mut local = parameters(Vec::new())?;
    local.expected_fdl1_digest = fdl1_digest(SandboxExecutionMode::Local, &local_layout())?;
    let inherited = vec![
        named(HOST_SERVICE_NAME, proxy),
        named(RELEASE_NAME, release),
    ];
    let worker = thread::spawn(move || {
        let error = run(&host, &environment(), &local, inherited).err();
        (error, host)
    });
    let (ready, _) = read_ready(&provider).ok_or("no ReadyV1")?;
    deliver(&provider, &release_with(|_| {}, &ready)?)?;
    let (error, host) = worker.join().map_err(|_| "panicked")?;
    assert!(matches!(error, Some(LauncherError::Exec(_))));
    assert_eq!(host.executions.lock().map_err(|_| "poisoned")?.len(), 1);
    // The proxy was open and no longer close-on-exec when the exec was
    // called; the release channel was already closed, so the provider sees EOF.
    assert_eq!(
        *host.inspected_cloexec.lock().map_err(|_| "poisoned")?,
        Some(false)
    );
    let mut buffer = [0_u8; 1];
    let closed = recvmsg(
        &provider,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::DONTWAIT,
    )?;
    assert_eq!(closed.bytes, 0);
    Ok(())
}

#[test]
fn the_process_host_reads_the_real_process() -> TestResult {
    let host = ProcessHost;
    assert_eq!(host.provider_uid(), 0);
    assert!(host.open_descriptors()?.iter().all(|number| *number >= 3));
    assert!(hold(host.open_launcher()?).is_ok());
    let first = host.monotonic_ns()?;
    assert!(host.monotonic_ns()? >= first);
    assert!(host.open_adapter("/proc/self/exe").is_err());
    assert!(host.open_adapter("/does/not/exist").is_err());
    let argv = [CString::new("/adapter")?];
    let empty = tempfile::tempfile()?;
    let refused = host.replace_process(&empty, &argv);
    assert!(refused.raw_os_error().is_some());
    Ok(())
}

#[test]
fn a_second_queued_release_is_a_duplicate_and_a_closed_peer_is_not() -> TestResult {
    let bytes = release_with(|_| {}, &ready_for_digest()?)?;

    let (provider, release) = pair(SocketType::SEQPACKET)?;
    deliver(&provider, &bytes)?;
    deliver(&provider, &bytes)?;
    assert!(matches!(
        receive_release(&release),
        Err(LauncherError::Release(ReleaseDefect::Duplicate))
    ));

    // A peer that sends one release and then closes leaves only EOF behind.
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    deliver(&provider, &bytes)?;
    drop(provider);
    assert!(receive_release(&release).is_ok());

    // A peer that is still connected and silent after the release is fine.
    let (provider, release) = pair(SocketType::SEQPACKET)?;
    deliver(&provider, &bytes)?;
    assert!(receive_release(&release).is_ok());
    drop(provider);
    Ok(())
}

fn ready_for_digest() -> Result<LauncherReady, Box<dyn Error>> {
    Ok(LauncherReady::new(
        pos_reference::sandbox_provider_protocol::LauncherReadyFields {
            attempt_id: ATTEMPT,
            nonce: NONCE,
            launch_instance_id: [5; 16],
            launcher_digest: [6; 32],
            launcher_identity: pos_reference::sandbox_provider_protocol::FdIdentity {
                mount_id: 1,
                inode: 2,
            },
            sim1_digest: SIM1,
            adapter_digest: [7; 32],
            adapter_identity: pos_reference::sandbox_provider_protocol::FdIdentity {
                mount_id: 1,
                inode: 3,
            },
            launch_parameter_digest: [8; 32],
            expected_fdl1_digest: [9; 32],
            observed_fdl1_digest: [9; 32],
        },
    )?)
}
