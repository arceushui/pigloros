use std::{
    error::Error,
    fs::File,
    io::{IoSlice, IoSliceMut, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::net::UnixStream as StdUnixStream,
    },
    process::Command,
    thread,
    time::Duration,
};

use rustix::{
    fs::fstat,
    io::{dup, fcntl_getfd, FdFlags},
    net::{
        recvmsg, sendmsg, sockopt, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
};
use tokio::net::UnixListener;

use super::*;

type BoxError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), BoxError>;
type Identity = (u64, u64);

const ROOT_OFFSET: u64 = 1_048_576;
const ROOT_SIZE: u64 = 8_388_608;

/// One `sendmsg` from the fake mountfsd, with fresh root fixture descriptors.
#[derive(Default)]
struct Chunk {
    bytes: Vec<u8>,
    descriptors: usize,
    extra: Vec<OwnedFd>,
}

/// What the fake mountfsd observed and returned.
struct Observed {
    call: Value,
    images: Vec<Identity>,
    root: Identity,
}

struct Transaction {
    outcome: Result<QuarantinedRootMount, ImageActivationError>,
    observed: Observed,
    held: Identity,
}

fn identity(descriptor: impl AsFd) -> Result<Identity, BoxError> {
    let stat = fstat(descriptor)?;
    Ok((stat.st_dev, stat.st_ino))
}

fn own_uid() -> Result<u32, BoxError> {
    let (local, _peer) = StdUnixStream::pair()?;
    Ok(sockopt::socket_peercred(&local)?.uid.as_raw())
}

fn valid_reply() -> Value {
    json!({"parameters": {
        "partitions": [{
            "designator": "root",
            "writable": false,
            "growFileSystem": false,
            "partitionNumber": 1,
            "architecture": "x86-64",
            "partitionUuid": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            "fileSystemType": "erofs",
            "partitionLabel": "root-x86-64",
            "size": ROOT_SIZE,
            "offset": ROOT_OFFSET,
            "mountFileDescriptor": 0,
            "mountPoint": ["/"],
        }],
        "singleFileSystem": false,
        "imagePolicy": policy::REQUESTED,
        "imageSize": 16_777_216,
        "sectorSize": 512,
        "imageName": "pigloros-subject",
        "imageUuid": "a7e6f6d2-61a4-4b52-9f3c-0c3c4b8f7a10",
    }})
}

fn with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut reply = valid_reply();
    edit(&mut reply);
    reply
}

fn root_field(reply: &mut Value, name: &str, value: Value) {
    reply["parameters"]["partitions"][0][name] = value;
}

fn message(reply: &Value) -> Result<Vec<u8>, BoxError> {
    let mut bytes = serde_json::to_vec(reply)?;
    bytes.push(0);
    Ok(bytes)
}

fn single(bytes: Vec<u8>, descriptors: usize) -> Vec<Chunk> {
    vec![Chunk {
        bytes,
        descriptors,
        ..Chunk::default()
    }]
}

fn receive_call(socket: &StdUnixStream) -> Result<(Value, Vec<OwnedFd>), BoxError> {
    let mut message = Vec::new();
    let mut descriptors = Vec::new();
    while message.last() != Some(&0) {
        let mut buffer = [0_u8; 4096];
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut buffer)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        for ancillary in control.drain() {
            if let RecvAncillaryMessage::ScmRights(incoming) = ancillary {
                descriptors.extend(incoming);
            }
        }
        if received.bytes == 0 {
            return Err("the call ended before its terminator".into());
        }
        message.extend_from_slice(&buffer[..received.bytes]);
    }
    message.pop();
    Ok((serde_json::from_slice(&message)?, descriptors))
}

fn send_chunk(socket: &StdUnixStream, chunk: &Chunk, root: &File) -> TestResult {
    let descriptors = (0..chunk.descriptors)
        .map(|_| root.try_clone().map(OwnedFd::from))
        .collect::<Result<Vec<_>, _>>()?;
    let borrowed: Vec<BorrowedFd<'_>> = descriptors
        .iter()
        .chain(&chunk.extra)
        .map(AsFd::as_fd)
        .collect();
    let mut space = vec![MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(32))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !borrowed.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
        return Err("the fixture descriptors exceed the control space".into());
    }
    let sent = sendmsg(
        socket,
        &[IoSlice::new(&chunk.bytes)],
        &mut control,
        SendFlags::empty(),
    )?;
    if sent == chunk.bytes.len() {
        Ok(())
    } else {
        Err("the fixture reply was sent short".into())
    }
}

/// A scripted mountfsd: read one call, then send each chunk in order.
fn serve(socket: &StdUnixStream, script: &[Chunk]) -> Result<Observed, BoxError> {
    let (call, images) = receive_call(socket)?;
    let mut root = tempfile::tempfile()?;
    root.write_all(b"detached root mount fixture")?;
    for chunk in script {
        send_chunk(socket, chunk, &root)?;
    }
    Ok(Observed {
        call,
        images: images.iter().map(identity).collect::<Result<_, _>>()?,
        root: identity(&root)?,
    })
}

async fn transact_with(
    script: Vec<Chunk>,
    architecture: SandboxArchitecture,
    configure: impl FnOnce(&StdUnixStream) -> TestResult + Send,
) -> Result<Transaction, BoxError> {
    let (client, server) = StdUnixStream::pair()?;
    configure(&client)?;
    client.set_nonblocking(true)?;
    let peer = thread::spawn(move || serve(&server, &script));
    let activator = MountfsdImageActivator::over(UnixStream::from_std(client)?, own_uid()?)?;
    let mut held = tempfile::tempfile()?;
    held.write_all(b"held SIM1 image")?;
    let image = ActivationImage {
        descriptor: OwnedFd::from(held.try_clone()?),
        root_offset: ROOT_OFFSET,
        root_size: ROOT_SIZE,
        architecture,
    };
    let outcome =
        tokio::time::timeout(Duration::from_secs(10), activator.mount_image(image)).await?;
    let observed = peer.join().map_err(|_| "the fake mountfsd panicked")??;
    Ok(Transaction {
        outcome,
        observed,
        held: identity(&held)?,
    })
}

async fn transact(script: Vec<Chunk>) -> Result<Transaction, BoxError> {
    transact_with(script, SandboxArchitecture::X86_64, |_| Ok(())).await
}

async fn outcome_of(reply: &Value, descriptors: usize) -> Result<ImageActivationError, BoxError> {
    transact(single(message(reply)?, descriptors))
        .await?
        .outcome
        .err()
        .ok_or_else(|| "the reply was accepted".into())
}

fn inherited_by_child(descriptor: RawFd) -> Result<bool, BoxError> {
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("test -e /proc/self/fd/{descriptor}"))
        .status()?;
    Ok(status.success())
}

#[tokio::test]
async fn one_call_sends_the_held_image_and_returns_one_sealed_root_mount() -> TestResult {
    let transaction = transact(single(message(&valid_reply())?, 1)).await?;
    assert_eq!(
        transaction.observed.call,
        json!({
            "method": "io.systemd.MountFileSystem.MountImage",
            "parameters": {
                "imageFileDescriptor": 0,
                "readOnly": true,
                "growFileSystems": false,
                "imagePolicy": "root=signed+erofs:=absent",
                "relaxExtensionReleaseChecks": false,
                "veritySharing": false,
                "allowInteractiveAuthentication": false,
            },
        })
    );
    assert_eq!(transaction.observed.images, vec![transaction.held]);
    let QuarantinedRootMount { _mount: mount } = transaction.outcome?;
    assert_eq!(identity(&mount)?, transaction.observed.root);
    assert!(fcntl_getfd(&mount)?.contains(FdFlags::CLOEXEC));
    // The sealed descriptor is not inherited across exec; an unsealed
    // duplicate of the same mount is, which shows the probe can observe it.
    assert!(!inherited_by_child(mount.as_raw_fd())?);
    let unsealed = dup(&mount)?;
    assert!(inherited_by_child(unsealed.as_raw_fd())?);
    Ok(())
}

#[tokio::test]
async fn the_v260_2_intersected_effective_policy_is_accepted() -> TestResult {
    // mountfsd returns image_policy_intersect(default, request); neither
    // default carries filesystem flags (proposed ADR-087 #439 amendment).
    for policy in ["root=signed:=absent", "root=signed+erofs:=absent"] {
        let reply = with(|reply| reply["parameters"]["imagePolicy"] = json!(policy));
        let transaction = transact(single(message(&reply)?, 1)).await?;
        assert!(transaction.outcome.is_ok(), "{policy}");
    }
    Ok(())
}

#[tokio::test]
async fn arm64_and_an_absent_architecture_are_accepted() -> TestResult {
    let arm64 = with(|reply| root_field(reply, "architecture", json!("arm64")));
    let transaction = transact_with(
        single(message(&arm64)?, 1),
        SandboxArchitecture::Aarch64,
        |_| Ok(()),
    )
    .await?;
    assert!(transaction.outcome.is_ok());
    let unnamed = with(|reply| {
        if let Some(root) = reply["parameters"]["partitions"][0].as_object_mut() {
            root.retain(|name, _| name != "architecture");
        }
    });
    assert!(transact(single(message(&unnamed)?, 1))
        .await?
        .outcome
        .is_ok());
    Ok(())
}

#[tokio::test]
async fn every_reply_outside_the_accepted_shape_is_malformed() -> TestResult {
    let cases = [
        with(|reply| root_field(reply, "mountFileDescriptor", json!(1))),
        with(|reply| root_field(reply, "mountFileDescriptor", json!(-1))),
        with(|reply| root_field(reply, "partitionNumber", json!(0))),
        with(|reply| root_field(reply, "unknown", json!(1))),
        with(|reply| reply["parameters"]["unknown"] = json!(1)),
        with(|reply| reply["parameters"]["partitions"] = json!([])),
        with(|reply| reply["parameters"]["partitions"] = json!(null)),
        with(|reply| {
            let root = reply["parameters"]["partitions"][0].clone();
            reply["parameters"]["partitions"] = json!([root.clone(), root]);
        }),
        with(|reply| {
            if let Some(parameters) = reply["parameters"].as_object_mut() {
                parameters.retain(|name, _| name != "imagePolicy");
            }
        }),
        with(|reply| reply["continues"] = json!(true)),
        json!({"error": "io.systemd.MountFileSystem.IncompatibleImage", "unknown": 1}),
    ];
    for reply in &cases {
        assert_eq!(
            outcome_of(reply, 1).await?,
            ImageActivationError::MalformedReply,
            "{reply}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_root_other_than_the_admitted_signed_erofs_root_is_an_evidence_mismatch() -> TestResult {
    let cases = [
        with(|reply| root_field(reply, "designator", json!("usr"))),
        with(|reply| root_field(reply, "writable", json!(true))),
        with(|reply| root_field(reply, "growFileSystem", json!(true))),
        with(|reply| root_field(reply, "fileSystemType", json!("squashfs"))),
        with(|reply| root_field(reply, "offset", json!(ROOT_OFFSET + 4096))),
        with(|reply| root_field(reply, "size", json!(ROOT_SIZE + 4096))),
        with(|reply| root_field(reply, "architecture", json!("arm64"))),
        with(|reply| reply["parameters"]["singleFileSystem"] = json!(true)),
    ];
    let policies = [
        "root=signed+squashfs:=absent",
        "root=signed+erofs+squashfs:=absent",
        "root=verity:=absent",
        "root=signed+read-only-on:=absent",
        "root=signed+growfs-on:=absent",
        "root=signed+unused:=absent",
        "root=signed:usr=signed:=absent",
        "root=signed:root-verity=absent:=absent",
        "root=signed:=ignore",
        "=absent",
    ];
    let cases = cases.into_iter().chain(
        policies
            .iter()
            .map(|policy| with(|reply| reply["parameters"]["imagePolicy"] = json!(policy))),
    );
    for reply in cases {
        assert_eq!(
            outcome_of(&reply, 1).await?,
            ImageActivationError::EvidenceMismatch,
            "{reply}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn duplicate_keys_and_non_json_replies_are_malformed() -> TestResult {
    let reply = serde_json::to_string(&valid_reply()["parameters"])?;
    let duplicated = format!("{{\"parameters\":{reply},\"parameters\":{reply}}}\0");
    for bytes in [duplicated.into_bytes(), b"not json\0".to_vec()] {
        let transaction = transact(single(bytes, 1)).await?;
        assert_eq!(
            transaction.outcome.err(),
            Some(ImageActivationError::MalformedReply)
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_descriptor_vector_other_than_one_root_mount_is_rejected() -> TestResult {
    let reply = message(&valid_reply())?;
    for descriptors in [0, 2, 16] {
        let transaction = transact(single(reply.clone(), descriptors)).await?;
        assert_eq!(
            transaction.outcome.err(),
            Some(ImageActivationError::MalformedReply),
            "{descriptors} descriptors"
        );
    }
    // Descriptors in two separate reads are two vectors for one message.
    let split = vec![
        Chunk {
            bytes: reply[..16].to_vec(),
            descriptors: 1,
            ..Chunk::default()
        },
        Chunk {
            bytes: reply[16..].to_vec(),
            descriptors: 1,
            ..Chunk::default()
        },
    ];
    assert_eq!(
        transact(split).await?.outcome.err(),
        Some(ImageActivationError::MalformedReply)
    );
    Ok(())
}

#[tokio::test]
async fn one_descriptor_in_a_later_read_is_still_the_one_vector() -> TestResult {
    let reply = message(&valid_reply())?;
    let later = vec![
        Chunk {
            bytes: reply[..16].to_vec(),
            descriptors: 0,
            ..Chunk::default()
        },
        Chunk {
            bytes: reply[16..].to_vec(),
            descriptors: 1,
            ..Chunk::default()
        },
    ];
    assert!(transact(later).await?.outcome.is_ok());
    Ok(())
}

/// A pipe whose write ends the fake mountfsd sends; the read end sees EOF
/// only once the client has closed every received copy.
fn closure_probe(copies: usize) -> Result<(std::io::PipeReader, Vec<OwnedFd>), BoxError> {
    let (reader, writer) = std::io::pipe()?;
    let writers = (0..copies)
        .map(|_| writer.try_clone().map(OwnedFd::from))
        .collect::<Result<Vec<_>, _>>()?;
    rustix::fs::fcntl_setfl(&reader, rustix::fs::OFlags::NONBLOCK)?;
    Ok((reader, writers))
}

#[tokio::test]
async fn every_rejected_descriptor_is_closed() -> TestResult {
    let valid = message(&valid_reply())?;
    let mismatch = message(&with(|reply| root_field(reply, "size", json!(1))))?;
    let rejected = message(&json!({"error": "io.systemd.MountFileSystem.VerityFailure"}))?;
    let cases = [
        (valid.clone(), 2, ImageActivationError::MalformedReply),
        (valid, 16, ImageActivationError::MalformedReply),
        (mismatch, 1, ImageActivationError::EvidenceMismatch),
        (rejected, 1, ImageActivationError::MethodRejected),
    ];
    for (bytes, copies, expected) in cases {
        let (mut reader, extra) = closure_probe(copies)?;
        let script = vec![Chunk {
            bytes,
            descriptors: 0,
            extra,
        }];
        assert_eq!(transact(script).await?.outcome.err(), Some(expected));
        let mut byte = [0_u8; 1];
        assert_eq!(
            std::io::Read::read(&mut reader, &mut byte)?,
            0,
            "{expected}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn framing_defects_are_malformed() -> TestResult {
    // The NUL of this fixture is not the last byte of a 256-byte zlink read,
    // so the trailing bytes arrive in the same read as the terminator.
    let mut trailing = message(&valid_reply())?;
    assert_ne!(trailing.len() % 256, 0);
    trailing.extend_from_slice(b"{}");
    let oversized = with(|reply| {
        reply["parameters"]["imageName"] = json!("x".repeat(70_000));
    });
    for bytes in [trailing, message(&oversized)?] {
        assert_eq!(
            transact(single(bytes, 1)).await?.outcome.err(),
            Some(ImageActivationError::MalformedReply)
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_unexpected_credentials_message_is_malformed() -> TestResult {
    let transaction = transact_with(
        single(message(&valid_reply())?, 1),
        SandboxArchitecture::X86_64,
        |client| Ok(sockopt::set_socket_passcred(client, true)?),
    )
    .await?;
    assert_eq!(
        transaction.outcome.err(),
        Some(ImageActivationError::MalformedReply)
    );
    Ok(())
}

#[tokio::test]
async fn varlink_errors_are_method_rejections() -> TestResult {
    let cases = [
        (
            json!({"error": "io.systemd.MountFileSystem.DeniedByImagePolicy"}),
            0,
        ),
        (
            json!({
                "error": "io.systemd.MountFileSystem.BadFileDescriptorFlags",
                "parameters": {"parameter": "imageFileDescriptor"},
            }),
            1,
        ),
        (
            json!({
                "error": "org.varlink.service.MethodNotFound",
                "parameters": {"method": "io.systemd.MountFileSystem.MountImage"},
            }),
            0,
        ),
    ];
    for (reply, descriptors) in &cases {
        assert_eq!(
            outcome_of(reply, *descriptors).await?,
            ImageActivationError::MethodRejected,
            "{reply}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_peer_closing_without_a_complete_reply_is_a_transport_failure() -> TestResult {
    let partial = message(&valid_reply())?[..32].to_vec();
    for script in [Vec::new(), single(partial, 1)] {
        assert_eq!(
            transact(script).await?.outcome.err(),
            Some(ImageActivationError::Transport)
        );
    }
    Ok(())
}

#[tokio::test]
async fn connection_failures_are_classified() -> TestResult {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing");
    let regular = directory.path().join("regular");
    File::create(&regular)?;
    let too_long = directory.path().join("x".repeat(200));
    for (path, expected) in [
        (&missing, ImageActivationError::HostFeatureUnavailable),
        (&regular, ImageActivationError::HostFeatureUnavailable),
        (&too_long, ImageActivationError::Transport),
    ] {
        let outcome = MountfsdImageActivator::connect_at(path, own_uid()?).await;
        assert_eq!(outcome.err(), Some(expected), "{}", path.display());
    }
    Ok(())
}

#[tokio::test]
async fn only_the_required_peer_identity_is_accepted() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("mountfsd");
    let _listener = UnixListener::bind(&path)?;
    let uid = own_uid()?;
    assert!(MountfsdImageActivator::connect_at(&path, uid).await.is_ok());
    assert_eq!(
        MountfsdImageActivator::connect_at(&path, uid.wrapping_add(1))
            .await
            .err(),
        Some(ImageActivationError::Transport)
    );
    Ok(())
}

#[test]
fn the_fixed_endpoint_is_the_root_mountfsd_socket() {
    assert_eq!(MOUNTFSD_SOCKET, "/run/systemd/io.systemd.MountFileSystem");
    assert_eq!(MOUNTFSD_PEER_UID, 0);
}

#[tokio::test]
async fn the_fixed_endpoint_is_unavailable_or_a_root_peer() {
    // Hosted runners have no mountfsd; a host that runs it must present root.
    let outcome = MountfsdImageActivator::connect().await;
    let unavailable = matches!(outcome, Err(ImageActivationError::HostFeatureUnavailable));
    assert!(outcome.is_ok() || unavailable);
}
