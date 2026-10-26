//! ADR-087 #439 composition through the real public chain.
//!
//! As root in the isolated container, the signed test installation is staged
//! at its fixed path, admitted through `ProviderImageSnapshot::open` and
//! `admit_held_image()`, and presented with `ActivationImage::from_admission`
//! to `MountfsdImageActivator::connect()`. A fake root mountfsd on the fixed
//! socket observes the one `MountImage` call. This proves which descriptor and
//! SIM1 root reach the wire, not a real mount (ADR-087 §5, #444).
#![cfg(target_os = "linux")]

#[path = "support/staged_execution.rs"]
pub mod staged_execution;

use std::{
    error::Error,
    fs,
    io::{IoSlice, IoSliceMut, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use pos_reference::provider_admission::{test_support::StagedInstallation, ProviderImageSnapshot};
use pos_sandboxd::{
    ActivationImage, ControlFloor, ImageActivationError, ImageActivator, MountfsdImageActivator,
    StagingError, StagingLedger, StagingLimits,
};
use rustix::{
    fs::fstat,
    net::{
        recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
    },
};
use serde_json::{json, Value};

type BoxError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), BoxError>;
type Identity = (u64, u64);

const PRIVILEGED_COMPOSITION_TEST: &str = "PIGLOROS_PRIVILEGED_COMPOSITION_TEST";
const MOUNTFSD_DIRECTORY: &str = "/run/systemd";
const MOUNTFSD_SOCKET: &str = "/run/systemd/io.systemd.MountFileSystem";

fn identity(descriptor: impl AsFd) -> Result<Identity, BoxError> {
    let stat = fstat(descriptor)?;
    Ok((stat.st_dev, stat.st_ino))
}

/// A v260.2-shaped reply describing the root partition at `offset`/`size`.
fn reply(offset: u64, size: u64) -> Result<Vec<u8>, BoxError> {
    reply_for(offset, size, "x86-64")
}

fn reply_for(offset: u64, size: u64, architecture: &str) -> Result<Vec<u8>, BoxError> {
    let mut bytes = serde_json::to_vec(&json!({"parameters": {
        "partitions": [{
            "designator": "root",
            "writable": false,
            "growFileSystem": false,
            "partitionNumber": 1,
            "architecture": architecture,
            "partitionUuid": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            "fileSystemType": "erofs",
            "partitionLabel": "root-x86-64",
            "size": size,
            "offset": offset,
            "mountFileDescriptor": 0,
            "mountPoint": ["/"],
        }],
        "singleFileSystem": false,
        "imagePolicy": "root=signed+erofs:=absent",
        "imageSize": 16_777_216,
        "sectorSize": 512,
        "imageName": "pigloros-subject",
        "imageUuid": "a7e6f6d2-61a4-4b52-9f3c-0c3c4b8f7a10",
    }}))?;
    bytes.push(0);
    Ok(bytes)
}

fn receive_call(socket: &UnixStream) -> Result<(Value, Vec<OwnedFd>), BoxError> {
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

/// What the fake mountfsd received in its one call.
struct Observed {
    call: Value,
    images: Vec<Identity>,
}

/// Accept one connection, read its call, and answer with `reply` plus one
/// regular-file stand-in for the detached root mount.
fn serve_once(listener: &UnixListener, reply: &[u8]) -> Result<Observed, BoxError> {
    let (socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (call, images) = receive_call(&socket)?;
    let mut root = tempfile::tempfile()?;
    root.write_all(b"detached root mount stand-in")?;
    let descriptors = [root.as_fd()];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err("the root descriptor exceeds the control space".into());
    }
    let sent = sendmsg(
        &socket,
        &[IoSlice::new(reply)],
        &mut control,
        SendFlags::empty(),
    )?;
    if sent != reply.len() {
        return Err("the fake reply was sent short".into());
    }
    Ok(Observed {
        call,
        images: images.iter().map(identity).collect::<Result<_, _>>()?,
    })
}

async fn activate(
    listener: &UnixListener,
    image: ActivationImage,
    reply: Vec<u8>,
) -> Result<(Result<(), ImageActivationError>, Observed), BoxError> {
    let listener = listener.try_clone()?;
    let peer = thread::spawn(move || serve_once(&listener, &reply));
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        MountfsdImageActivator::connect()
            .await?
            .mount_image(image)
            .await
            .map(drop)
    })
    .await?;
    let observed = peer.join().map_err(|_| "the fake mountfsd panicked")??;
    Ok((outcome, observed))
}

fn run_isolated(test_name: &str) -> TestResult {
    let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
    let output = Command::new(runner)
        .arg(std::env::current_exe()?)
        .arg(test_name)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "isolated test {test_name} failed with {}:\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

#[tokio::test]
async fn activation_image_carries_exactly_the_held_admitted_image() -> TestResult {
    if std::env::var_os(PRIVILEGED_COMPOSITION_TEST).is_none() {
        return run_isolated("activation_image_carries_exactly_the_held_admitted_image");
    }
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err("the isolated activation child is not root".into());
    }
    let staged = StagedInstallation::stage_execution().map_err(|error| error.to_string())?;
    let snapshot = ProviderImageSnapshot::open(staged.request())?;
    let limits = StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    };
    let ledger = StagingLedger::new(limits);
    let (_staging, verified) = staged_execution::verified_input(&staged, &ledger)?;
    let entry = verified.entry();
    assert_eq!(ledger.usage().attempts, 1);
    entry.recheck()?;
    let admission = entry.admission();
    let installed = admission.authority();
    let held = identity(&admission)?;
    let root = &snapshot.image().manifest().partitions[0];
    fs::create_dir(MOUNTFSD_DIRECTORY)?;
    let listener = UnixListener::bind(MOUNTFSD_SOCKET)?;

    // The admitted SIM1 root partition is what the reply must describe.
    let (outcome, observed) = activate(
        &listener,
        ActivationImage::from_admission(&admission)?,
        reply(root.start_bytes, root.length_bytes)?,
    )
    .await?;
    outcome?;
    assert_eq!(observed.images, vec![held]);
    assert_eq!(observed.call["parameters"]["imageFileDescriptor"], 0);
    assert_eq!(
        observed.call["parameters"]["imagePolicy"],
        "root=signed+erofs:=absent"
    );

    // Any other root, here the verity partition's extent, is a mismatch.
    let verity = &snapshot.image().manifest().partitions[1];
    let (outcome, observed) = activate(
        &listener,
        ActivationImage::from_admission(&admission)?,
        reply(verity.start_bytes, verity.length_bytes)?,
    )
    .await?;
    assert_eq!(outcome, Err(ImageActivationError::EvidenceMismatch));
    assert_eq!(observed.images, vec![held]);

    // The admitted SIM1 is x86-64: the right extent of another
    // architecture is a mismatch too.
    let (outcome, observed) = activate(
        &listener,
        ActivationImage::from_admission(&admission)?,
        reply_for(root.start_bytes, root.length_bytes, "arm64")?,
    )
    .await?;
    assert_eq!(outcome, Err(ImageActivationError::EvidenceMismatch));
    assert_eq!(observed.images, vec![held]);

    // Immediately before launch, a floor above the admission refuses, and a
    // pending recovery (here a pending SIR1) makes the authority unreadable.
    ledger.raise_floor(ControlFloor {
        revocation_epoch: installed.revocation_epoch + 1,
        policy_epoch: 0,
    });
    assert!(matches!(
        entry.recheck(),
        Err(StagingError::BelowControlFloor)
    ));
    fs::write("/var/lib/pigloros/sandbox/installation-update.cbor", [1_u8])?;
    assert!(matches!(
        entry.recheck(),
        Err(StagingError::AuthorityChanged)
    ));
    Ok(())
}
