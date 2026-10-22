use std::{
    cell::Cell,
    error::Error,
    fs::File,
    io::{IoSlice, IoSliceMut},
    mem::MaybeUninit,
    os::fd::{AsFd, OwnedFd},
};

use ed25519_dalek::SigningKey;
use pos_reference::sandbox_provider_protocol::{ExecutionRelease, FdIdentity, LauncherReady};
use rustix::{
    net::{
        recvmsg, sendmsg, socketpair, AddressFamily, RecvAncillaryBuffer, RecvFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, UCred,
    },
    process::{getgid, getpid, getuid},
};

use super::{
    release_after_ready, ExpectedLauncherReady, ReleaseBarrierError, ReleaseBinding, ReleaseRecheck,
};
use crate::release_signer::{ReleaseSigner, ReleaseSignerError};

type TestResult = Result<(), Box<dyn Error>>;

const KEY_ID: &str = "runtime-key";

fn expected() -> ExpectedLauncherReady {
    ExpectedLauncherReady {
        attempt_id: [1; 16],
        nonce: [2; 32],
        launch_instance_id: [3; 16],
        launcher_digest: [4; 32],
        launcher_identity: FdIdentity {
            mount_id: 5,
            inode: 6,
        },
        sim1_digest: [7; 32],
        adapter_digest: [8; 32],
        adapter_identity: FdIdentity {
            mount_id: 9,
            inode: 10,
        },
        launch_parameter_digest: [11; 32],
        expected_fdl1_digest: [12; 32],
    }
}

fn binding() -> ReleaseBinding {
    ReleaseBinding {
        trs1_digest: [21; 32],
        rvs1_digest: [22; 32],
        apt1_digest: [23; 32],
        trust_epoch: 1,
        revocation_epoch: 2,
        policy_epoch: 3,
        expected_readback_digest: [24; 32],
        observed_readback_digest: [24; 32],
        deadline_monotonic_ns: 9_000,
    }
}

struct Recheck {
    result: Result<ReleaseBinding, ()>,
    calls: Cell<u32>,
}

impl Recheck {
    fn allow() -> Self {
        Self {
            result: Ok(binding()),
            calls: Cell::new(0),
        }
    }
}

impl ReleaseRecheck for Recheck {
    fn recheck(&self) -> Result<ReleaseBinding, ReleaseBarrierError> {
        self.calls.set(self.calls.get() + 1);
        self.result
            .clone()
            .map_err(|()| ReleaseBarrierError::Recheck)
    }
}

struct Signer {
    key: SigningKey,
    zero_signature: bool,
}

impl Signer {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[42; 32]),
            zero_signature: false,
        }
    }
}

impl ReleaseSigner for Signer {
    fn runtime_attestation_key_id(&self) -> &str {
        KEY_ID
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        if self.zero_signature {
            [0; 64]
        } else {
            ed25519_dalek::Signer::sign(&self.key, message).to_bytes()
        }
    }
}

fn pair() -> Result<(OwnedFd, OwnedFd), Box<dyn Error>> {
    Ok(socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?)
}

fn ready_bytes(expected: &ExpectedLauncherReady) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(LauncherReady::new(expected.fields())?.to_canonical_cbor()?)
}

/// The launcher side: one datagram with this process's credentials.
fn launcher_sends(launcher: &OwnedFd, bytes: &[u8]) -> TestResult {
    let credentials = UCred {
        pid: getpid(),
        uid: getuid(),
        gid: getgid(),
    };
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmCredentials(credentials)));
    sendmsg(
        launcher,
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    Ok(())
}

fn pid() -> Result<u32, Box<dyn Error>> {
    Ok(u32::try_from(getpid().as_raw_nonzero().get())?)
}

fn error_of(
    bytes: &[u8],
    main_pid: u32,
    expected: &ExpectedLauncherReady,
    recheck: &Recheck,
    signer: &Signer,
) -> Result<ReleaseBarrierError, Box<dyn Error>> {
    let (provider, launcher) = pair()?;
    launcher_sends(&launcher, bytes)?;
    Ok(
        release_after_ready(&provider, main_pid, expected, recheck, signer)
            .err()
            .ok_or("the barrier released")?,
    )
}

#[test]
fn a_matching_ready_is_released_once_with_the_rechecked_authority() -> TestResult {
    let expected = expected();
    let (provider, launcher) = pair()?;
    launcher_sends(&launcher, &ready_bytes(&expected)?)?;
    let recheck = Recheck::allow();
    let signer = Signer::new();
    let release = release_after_ready(&provider, pid()?, &expected, &recheck, &signer)?;
    assert_eq!(recheck.calls.get(), 1);

    let mut buffer = [0_u8; 4096];
    let received = recvmsg(
        &launcher,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::empty(),
    )?;
    let sent = ExecutionRelease::from_canonical_cbor(&buffer[..received.bytes])?;
    assert_eq!(sent, release);
    sent.verify_signature(&signer.key.verifying_key())?;
    let ready = LauncherReady::new(expected.fields())?;
    let fields = &sent.fields;
    assert_eq!(fields.attempt_id, expected.attempt_id);
    assert_eq!(fields.nonce, expected.nonce);
    assert_eq!(fields.ready1_digest, ready.digest);
    assert_eq!(fields.trs1_digest, [21; 32]);
    assert_eq!(fields.rvs1_digest, [22; 32]);
    assert_eq!(fields.apt1_digest, [23; 32]);
    assert_eq!(
        (
            fields.trust_epoch,
            fields.revocation_epoch,
            fields.policy_epoch
        ),
        (1, 2, 3)
    );
    assert_eq!(fields.deadline_monotonic_ns, 9_000);
    assert_eq!(fields.runtime_attestation_key_id, KEY_ID);
    // Nothing else was sent.
    let again = recvmsg(
        &launcher,
        &mut [IoSliceMut::new(&mut buffer)],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::DONTWAIT,
    );
    assert!(again.is_err());
    Ok(())
}

#[test]
fn a_ready_from_another_pid_is_refused_without_a_recheck() -> TestResult {
    let expected = expected();
    let recheck = Recheck::allow();
    let error = error_of(
        &ready_bytes(&expected)?,
        pid()?.wrapping_add(1),
        &expected,
        &recheck,
        &Signer::new(),
    )?;
    assert!(matches!(error, ReleaseBarrierError::PidMismatch));
    assert_eq!(recheck.calls.get(), 0);
    Ok(())
}

#[test]
fn every_ready_binding_must_equal_the_expected_evidence() -> TestResult {
    let expected = expected();
    let mutations: Vec<Box<dyn Fn(&mut ExpectedLauncherReady)>> = vec![
        Box::new(|e| e.attempt_id = [9; 16]),
        Box::new(|e| e.nonce = [9; 32]),
        Box::new(|e| e.launch_instance_id = [9; 16]),
        Box::new(|e| e.launcher_digest = [9; 32]),
        Box::new(|e| e.launcher_identity.inode += 1),
        Box::new(|e| e.launcher_identity.mount_id += 1),
        Box::new(|e| e.sim1_digest = [9; 32]),
        Box::new(|e| e.adapter_digest = [9; 32]),
        Box::new(|e| e.adapter_identity.inode += 1),
        Box::new(|e| e.adapter_identity.mount_id += 1),
        Box::new(|e| e.launch_parameter_digest = [9; 32]),
        Box::new(|e| e.expected_fdl1_digest = [9; 32]),
    ];
    for mutate in mutations {
        let mut sent = expected.clone();
        mutate(&mut sent);
        let recheck = Recheck::allow();
        let error = error_of(
            &ready_bytes(&sent)?,
            pid()?,
            &expected,
            &recheck,
            &Signer::new(),
        )?;
        assert!(matches!(error, ReleaseBarrierError::ReadyMismatch));
        assert_eq!(recheck.calls.get(), 0);
    }
    // An observed layout that differs from the expected one is a mismatch too.
    let mut fields = expected.fields();
    fields.observed_fdl1_digest = [9; 32];
    let bytes = LauncherReady::new(fields)?.to_canonical_cbor()?;
    let error = error_of(&bytes, pid()?, &expected, &Recheck::allow(), &Signer::new())?;
    assert!(matches!(error, ReleaseBarrierError::ReadyMismatch));
    Ok(())
}

#[test]
fn malformed_oversized_and_control_carrying_ready_datagrams_are_refused() -> TestResult {
    let expected = expected();
    let recheck = Recheck::allow();
    let signer = Signer::new();
    let malformed = error_of(b"not cbor", pid()?, &expected, &recheck, &signer)?;
    assert!(matches!(malformed, ReleaseBarrierError::ReadyMalformed));
    let oversized = error_of(&[0_u8; 5000], pid()?, &expected, &recheck, &signer)?;
    assert!(matches!(oversized, ReleaseBarrierError::ReadyFraming));
    let empty = error_of(b"", pid()?, &expected, &recheck, &signer)?;
    assert!(matches!(empty, ReleaseBarrierError::ReadyUnavailable));

    // A descriptor next to the credentials is control data the provider refuses.
    let (provider, launcher) = pair()?;
    let spare = File::open("/")?;
    let borrowed = [spare.as_fd()];
    let credentials = UCred {
        pid: getpid(),
        uid: getuid(),
        gid: getgid(),
    };
    let bytes = ready_bytes(&expected)?;
    let mut space =
        [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1), ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    assert!(control.push(SendAncillaryMessage::ScmCredentials(credentials)));
    assert!(control.push(SendAncillaryMessage::ScmRights(&borrowed)));
    sendmsg(
        &launcher,
        &[IoSlice::new(&bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )?;
    let error = release_after_ready(&provider, pid()?, &expected, &recheck, &signer)
        .err()
        .ok_or("released")?;
    assert!(matches!(error, ReleaseBarrierError::ReadyFraming));
    assert_eq!(recheck.calls.get(), 0);
    Ok(())
}

#[test]
fn a_closed_launcher_and_a_non_socket_channel_are_unavailable() -> TestResult {
    let (provider, launcher) = pair()?;
    drop(launcher);
    let error = release_after_ready(
        &provider,
        pid()?,
        &expected(),
        &Recheck::allow(),
        &Signer::new(),
    )
    .err()
    .ok_or("released")?;
    assert!(matches!(error, ReleaseBarrierError::ReadyUnavailable));

    let file = File::open("/")?;
    let error = release_after_ready(
        &file,
        pid()?,
        &expected(),
        &Recheck::allow(),
        &Signer::new(),
    )
    .err()
    .ok_or("released")?;
    assert!(matches!(error, ReleaseBarrierError::ReadyUnavailable));
    Ok(())
}

#[test]
fn a_failed_recheck_signing_failure_or_closed_launcher_sends_no_release() -> TestResult {
    let expected = expected();
    let bytes = ready_bytes(&expected)?;

    let (provider, launcher) = pair()?;
    launcher_sends(&launcher, &bytes)?;
    let refusing = Recheck {
        result: Err(()),
        calls: Cell::new(0),
    };
    let error = release_after_ready(&provider, pid()?, &expected, &refusing, &Signer::new())
        .err()
        .ok_or("released")?;
    assert!(matches!(error, ReleaseBarrierError::Recheck));
    assert_eq!(refusing.calls.get(), 1);
    assert!(recvmsg(
        &launcher,
        &mut [IoSliceMut::new(&mut [0_u8; 8])],
        &mut RecvAncillaryBuffer::new(&mut []),
        RecvFlags::DONTWAIT,
    )
    .is_err());

    let (provider, launcher) = pair()?;
    launcher_sends(&launcher, &bytes)?;
    let zero = Signer {
        zero_signature: true,
        ..Signer::new()
    };
    let error = release_after_ready(&provider, pid()?, &expected, &Recheck::allow(), &zero)
        .err()
        .ok_or("released")?;
    assert!(matches!(
        error,
        ReleaseBarrierError::Sign(ReleaseSignerError::Protocol(_))
    ));

    let (provider, launcher) = pair()?;
    launcher_sends(&launcher, &bytes)?;
    drop(launcher);
    let error = release_after_ready(
        &provider,
        pid()?,
        &expected,
        &Recheck::allow(),
        &Signer::new(),
    )
    .err()
    .ok_or("released")?;
    assert!(matches!(error, ReleaseBarrierError::ReleaseSend));
    Ok(())
}
