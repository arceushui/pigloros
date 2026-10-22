//! The ReadyV1/ReleaseV1 exchange (ADR-069 "Requested state, observed state,
//! and release barrier").

use std::{
    convert::Infallible,
    ffi::CString,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::OwnedFd,
    time::Duration,
};

use pos_reference::sandbox_provider_protocol::{
    fdl1_digest, ExecutionRelease, FdLayoutEntry, LaunchParameters, LauncherReady,
    LauncherReadyFields, SandboxExecutionMode,
};
use rustix::{
    io::{fcntl_setfd, Errno, FdFlags},
    net::{
        recvmsg, sendmsg,
        sockopt::{set_socket_timeout, socket_peercred, Timeout},
        RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
        SendFlags, UCred,
    },
    process::getgid,
    process::getpid,
    process::getuid,
};

use super::{
    adapter::{hold, hold_adapter},
    descriptors::{validate, Inherited, InheritedLayout},
    environment::LaunchEnvironment,
    error::{LauncherError, ReleaseDefect},
    host::LaunchHost,
};

const TRUNCATED: ReturnFlags = ReturnFlags::TRUNC.union(ReturnFlags::CTRUNC);
/// The launcher waits at most this long for `ReleaseV1` after `ReadyV1`
/// (ADR-069: 30 seconds; the canonical constant belongs to #212 and a provider
/// may only be stricter).
pub(super) const RELEASE_WAIT: Duration = Duration::from_secs(30);
/// Largest `ReleaseV1` datagram the launcher accepts.
const MAX_RELEASE_BYTES: usize = 4096;
const MODES: [SandboxExecutionMode; 4] = [
    SandboxExecutionMode::Local,
    SandboxExecutionMode::AirGapped,
    SandboxExecutionMode::Replay,
    SandboxExecutionMode::Fork,
];

/// Run the complete barrier. It returns only the reason the adapter was not
/// executed; a released adapter replaces the process image instead.
pub(super) fn run(
    host: &impl LaunchHost,
    environment: &LaunchEnvironment,
    parameters: &LaunchParameters,
    inherited: Inherited,
) -> Result<Infallible, LauncherError> {
    let open = host.open_descriptors().map_err(|_| LauncherError::Layout)?;
    let layout = validate(inherited, &open)?;
    socket_peercred(&layout.release)
        .is_ok_and(|credentials| credentials.uid.as_raw() == host.provider_uid())
        .then_some(())
        .ok_or(LauncherError::Peer)?;
    let observed_fdl1_digest = observed_fdl1(parameters.expected_fdl1_digest, &layout.entries)?;
    let adapter = hold_adapter(
        host.open_adapter(&parameters.adapter_path)
            .map_err(|_| LauncherError::Adapter)?,
    )?;
    let launcher = hold(host.open_launcher().map_err(|_| LauncherError::Identity)?)?;
    // Built before ReadyV1, so a bad vector is refused before the provider can release.
    let argv = argument_vector(parameters)?;
    let (ready, ready_bytes) = LauncherReady::new(LauncherReadyFields {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        launch_instance_id: environment.launch_instance_id,
        launcher_digest: launcher.digest,
        launcher_identity: launcher.identity,
        sim1_digest: parameters.sim1_digest,
        adapter_digest: adapter.digest,
        adapter_identity: adapter.identity,
        launch_parameter_digest: parameters.digest,
        expected_fdl1_digest: parameters.expected_fdl1_digest,
        observed_fdl1_digest,
    })
    .and_then(|ready| ready.to_canonical_cbor().map(|bytes| (ready, bytes)))
    .map_err(|_| LauncherError::Ready)?;
    send_ready(&layout.release, &ready_bytes)?;
    let release = receive_release(&layout.release, RELEASE_WAIT)?;
    let now = host
        .monotonic_ns()
        .map_err(|_| LauncherError::ReleaseUnavailable)?;
    check_release(&release, parameters, &ready, now)?;
    let InheritedLayout {
        release: channel,
        host_service,
        ..
    } = layout;
    drop(channel);
    // Only the Local proxy survives into the adapter, as its FD 3.
    if let Some(proxy) = &host_service {
        // If this failed the proxy would stay close-on-exec and the adapter
        // would start without it: the safe direction, so the result is not
        // acted on.
        fcntl_setfd(proxy, FdFlags::empty()).ok();
    }
    Err(LauncherError::Exec(
        host.replace_process(&adapter.file, &argv),
    ))
}

/// The FDL1 digest of the scanned layout under whichever mode it matches.
///
/// LPV1 carries only the expected digest, not the mode. Air-Gapped, Replay and
/// Fork share one layout, so the observed digest is the one of the mode whose
/// digest equals the expected one; no mode matching rejects before `ReadyV1`.
fn observed_fdl1(expected: [u8; 32], entries: &[FdLayoutEntry]) -> Result<[u8; 32], LauncherError> {
    MODES
        .into_iter()
        .filter_map(|mode| fdl1_digest(mode, entries).ok())
        .find(|digest| *digest == expected)
        .ok_or(LauncherError::Layout)
}

pub(super) fn send_ready(release: &OwnedFd, bytes: &[u8]) -> Result<(), LauncherError> {
    let credentials = UCred {
        pid: getpid(),
        uid: getuid(),
        gid: getgid(),
    };
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let sent = control.push(SendAncillaryMessage::ScmCredentials(credentials))
        && sendmsg(
            release,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .is_ok_and(|written| written == bytes.len());
    sent.then_some(()).ok_or(LauncherError::Ready)
}

/// Receive exactly one complete `ReleaseV1` datagram with no control data,
/// then prove no second message is already queued.
pub(super) fn receive_release(
    release: &OwnedFd,
    wait: Duration,
) -> Result<ExecutionRelease, LauncherError> {
    // A failure to arm the timeout leaves the wait unbounded, so it refuses.
    set_socket_timeout(release, Timeout::Recv, Some(wait))
        .ok()
        .ok_or(LauncherError::ReleaseUnavailable)?;
    let mut buffer = [0_u8; MAX_RELEASE_BYTES];
    let received = recvmsg(
        release,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::empty(),
    )
    .ok()
    .filter(|received| received.bytes != 0)
    .ok_or(LauncherError::ReleaseUnavailable)?;
    if received.flags.intersects(TRUNCATED) {
        return Err(LauncherError::Release(ReleaseDefect::Malformed));
    }
    let record = ExecutionRelease::from_canonical_cbor(&buffer[..received.bytes])
        .map_err(|_| LauncherError::Release(ReleaseDefect::Malformed))?;
    let mut probe = [0_u8; 1];
    // Anything but "nothing queued" (a message, or an error that cannot rule
    // one out) is treated as a duplicate. A closed peer reads as zero bytes.
    let queued = recvmsg(
        release,
        &mut [IoSliceMut::new(&mut probe)],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::DONTWAIT,
    )
    .map_or_else(|error| error != Errno::AGAIN, |next| next.bytes != 0);
    if queued {
        Err(LauncherError::Release(ReleaseDefect::Duplicate))
    } else {
        Ok(record)
    }
}

fn check_release(
    release: &ExecutionRelease,
    parameters: &LaunchParameters,
    ready: &LauncherReady,
    now_monotonic_ns: u64,
) -> Result<(), LauncherError> {
    let fields = &release.fields;
    let defect = if fields.attempt_id != parameters.attempt_id {
        Some(ReleaseDefect::Attempt)
    } else if fields.nonce != parameters.nonce {
        Some(ReleaseDefect::Nonce)
    } else if fields.ready1_digest != ready.digest {
        Some(ReleaseDefect::ReadyDigest)
    } else if fields.deadline_monotonic_ns <= now_monotonic_ns {
        Some(ReleaseDefect::Expired)
    } else {
        None
    };
    defect.map_or(Ok(()), |defect| Err(LauncherError::Release(defect)))
}

/// `argv[0]` is the adapter path, followed by the fixed LPV1 arguments.
fn argument_vector(parameters: &LaunchParameters) -> Result<Vec<CString>, LauncherError> {
    std::iter::once(&parameters.adapter_path)
        .chain(&parameters.arguments)
        .map(|argument| CString::new(argument.as_str()))
        .collect::<Result<_, _>>()
        .map_err(|_| LauncherError::Parameters)
}
