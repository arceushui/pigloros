use std::{
    io::IoSlice,
    mem::MaybeUninit,
    os::fd::OwnedFd as StdOwnedFd,
    thread::{self, JoinHandle},
};

use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{LauncherReady, LauncherReadyFields};
use rustix::{
    net::{recv, sendmsg, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, UCred},
    process::{getgid, getpid, getuid},
};

use super::*;
use crate::{
    test_fixtures::{authority, TestResult, ATTEMPT},
    ActivatedRootDirectory,
};

const KEY_ID: &str = "runtime-key";
const EXPECTED_READBACK: [u8; 32] = [5; 32];
const OBSERVED_READBACK: [u8; 32] = [6; 32];
const LAUNCHER_DIGEST: [u8; 32] = [0x71; 32];
const INVOCATION: [u8; 16] = [0x12; 16];
const ADAPTER_IDENTITY: FdIdentity = FdIdentity {
    mount_id: 9,
    inode: 77,
};
const GENEROUS_MS: u64 = 30_000;

struct TestSigner {
    key: SigningKey,
}

impl ReleaseSigner for TestSigner {
    fn runtime_attestation_key_id(&self) -> &str {
        KEY_ID
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the unit identity is unavailable")]
struct IdentityDown;

struct TestIdentity {
    pid: u32,
    broken: bool,
}

impl UnitIdentitySource for TestIdentity {
    type Error = IdentityDown;

    fn main_pid(
        &self,
        _unit_name: &TransientServiceUnitName,
    ) -> impl Future<Output = Result<u32, IdentityDown>> + Send {
        let outcome = if self.broken {
            Err(IdentityDown)
        } else {
            Ok(self.pid)
        };
        async move { outcome }
    }

    async fn invocation_id(
        &self,
        _unit_name: &TransientServiceUnitName,
    ) -> Result<[u8; 16], IdentityDown> {
        Ok(INVOCATION)
    }
}

struct TestObserved(Option<[u8; 32]>);

impl ObservedReadback for TestObserved {
    fn observed_digest(&self) -> Result<[u8; 32], ObservedReadbackUnavailable> {
        self.0.ok_or(ObservedReadbackUnavailable)
    }
}

#[derive(Clone, Copy)]
enum Refusal {
    None,
    Cancelled,
    RootFails,
    NoObservation,
}

type RootCheck = Box<dyn Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync>;
type TestBarrier = ProviderReleaseBarrier<TestSigner, TestIdentity, RootCheck, TestObserved>;

fn root_check(refusal: Refusal) -> RootCheck {
    if matches!(refusal, Refusal::RootFails) {
        Box::new(|| Err(ImageActivationError::EvidenceMismatch))
    } else {
        Box::new(|| {
            Ok(CheckedRoot::for_test(ActivatedRootDirectory::for_attempt(
                "00000000000000000000000000000041",
            )))
        })
    }
}

/// A barrier whose manager reports `claimed_pid`, plus its admitted attempt.
fn barrier_for(
    mode: SandboxExecutionMode,
    refusal: Refusal,
    claimed_pid: u32,
) -> TestResult<(TestBarrier, AdmittedAttempt)> {
    let attempt = AdmittedAttempt::for_test(ATTEMPT, authority(), mode)?;
    let observed = (!matches!(refusal, Refusal::NoObservation)).then_some(OBSERVED_READBACK);
    let cancelled = Arc::new(AtomicBool::new(matches!(refusal, Refusal::Cancelled)));
    let check = AuthorityCheck::new(
        authority(),
        root_check(refusal),
        EXPECTED_READBACK,
        TestObserved(observed),
        cancelled,
    );
    let barrier = ProviderReleaseBarrier::new(
        &attempt,
        mode,
        [0x33; 32],
        BarrierEvidence {
            launcher_digest: LAUNCHER_DIGEST,
            adapter_identity: ADAPTER_IDENTITY,
        },
        TestSigner {
            key: SigningKey::from_bytes(&[9; 32]),
        },
        TestIdentity {
            pid: claimed_pid,
            broken: false,
        },
        check,
    )?;
    Ok((barrier, attempt))
}

fn own_pid() -> u32 {
    std::process::id()
}

fn ready_for(barrier: &TestBarrier) -> TestResult<LauncherReady> {
    let parameters = &barrier.parameters;
    Ok(LauncherReady::new(LauncherReadyFields {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        launch_instance_id: INVOCATION,
        launcher_digest: LAUNCHER_DIGEST,
        launcher_identity: observe_executable(own_pid())?,
        sim1_digest: parameters.sim1_digest,
        adapter_digest: barrier.adapter_digest,
        adapter_identity: ADAPTER_IDENTITY,
        launch_parameter_digest: parameters.digest,
        expected_fdl1_digest: parameters.expected_fdl1_digest,
        observed_fdl1_digest: parameters.expected_fdl1_digest,
    })?)
}

fn send_ready(unit_end: &StdOwnedFd, bytes: &[u8]) -> Option<()> {
    let credentials = UCred {
        pid: getpid(),
        uid: getuid(),
        gid: getgid(),
    };
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    control
        .push(SendAncillaryMessage::ScmCredentials(credentials))
        .then_some(())?;
    sendmsg(
        unit_end,
        &[IoSlice::new(bytes)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .ok()
    .map(|_| ())
}

fn receive_release(unit_end: &StdOwnedFd) -> Option<ExecutionRelease> {
    set_socket_timeout(unit_end, Timeout::Recv, Some(Duration::from_secs(5))).ok()?;
    let mut buffer = vec![0_u8; 4096];
    let (received, _) = recv(unit_end, &mut buffer, RecvFlags::empty()).ok()?;
    ExecutionRelease::from_canonical_cbor(&buffer[..received]).ok()
}

/// A launcher that answers with a correct `ReadyV1` and reports the release it
/// receives.
fn launcher(barrier: &mut TestBarrier) -> TestResult<JoinHandle<Option<ExecutionRelease>>> {
    let unit_end = StdOwnedFd::from(barrier.take_unit_end()?);
    let ready = ready_for(barrier)?.to_canonical_cbor()?;
    Ok(thread::spawn(move || {
        send_ready(&unit_end, &ready)?;
        receive_release(&unit_end)
    }))
}

fn active(attempt: AdmittedAttempt, milliseconds: u64) -> ActiveAttempt {
    ActiveAttempt::record(
        attempt,
        Instant::now() + Duration::from_millis(milliseconds),
    )
}

fn monotonic_ns() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    u64::try_from(now.tv_sec).unwrap_or_default() * NANOSECONDS_PER_SECOND
        + u64::try_from(now.tv_nsec).unwrap_or_default()
}

fn check_release(barrier: &TestBarrier, received: Option<&ExecutionRelease>) -> TestResult {
    let sent = barrier.sent_release();
    assert_eq!(received, sent);
    let release = sent.ok_or("no release was sent")?;
    let fields = &release.fields;
    assert_eq!(fields.attempt_id, ATTEMPT);
    assert_eq!(fields.nonce, barrier.parameters.nonce);
    assert_eq!(fields.expected_readback_digest, EXPECTED_READBACK);
    assert_eq!(fields.observed_readback_digest, OBSERVED_READBACK);
    assert_eq!(fields.runtime_attestation_key_id, KEY_ID);
    assert!(fields.deadline_monotonic_ns > monotonic_ns());
    release.verify_signature(&SigningKey::from_bytes(&[9; 32]).verifying_key())?;
    Ok(())
}

fn check_authority(release: &ExecutionRelease) {
    let admitted = authority();
    assert_eq!(release.fields.trs1_digest, admitted.trs1_digest);
    assert_eq!(release.fields.rvs1_digest, admitted.rvs1_digest);
    assert_eq!(release.fields.apt1_digest, admitted.apt1_digest);
    assert_eq!(release.fields.trust_epoch, admitted.trust_epoch);
    assert_eq!(release.fields.revocation_epoch, admitted.revocation_epoch);
    assert_eq!(release.fields.policy_epoch, admitted.policy_epoch);
}

/// Release a correct `ReadyV1` and return what the launcher received.
async fn released() -> TestResult<(TestBarrier, Option<ExecutionRelease>)> {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::Local, Refusal::None, own_pid())?;
    let launcher = launcher(&mut barrier)?;
    assert!(barrier.sent_release().is_none());
    barrier.release(&active(attempt, GENEROUS_MS)).await?;
    let received = launcher.join().map_err(|_| "launcher thread")?;
    Ok((barrier, received))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_ready_is_released_once_with_the_admitted_bindings() -> TestResult {
    let (barrier, received) = released().await?;
    check_release(&barrier, received.as_ref())?;
    check_authority(&received.ok_or("no release received")?);
    Ok(())
}

async fn refused(refusal: Refusal, claimed_pid: u32) -> TestResult<BarrierError> {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, refusal, claimed_pid)?;
    let launcher = launcher(&mut barrier)?;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(barrier.sent_release().is_none());
    // The launcher is never answered: closing the channel shows it no release.
    drop(barrier);
    assert_eq!(launcher.join().map_err(|_| "launcher thread")?, None);
    error.ok_or_else(|| "the release was not refused".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_attempt_is_not_released() -> TestResult {
    let error = refused(Refusal::Cancelled, own_pid()).await?;
    assert!(matches!(
        error,
        BarrierError::Release(ReleaseBarrierError::Recheck)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_root_recheck_is_not_released() -> TestResult {
    let error = refused(Refusal::RootFails, own_pid()).await?;
    assert!(matches!(
        error,
        BarrierError::Release(ReleaseBarrierError::Recheck)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_observed_readback_is_not_released() -> TestResult {
    let error = refused(Refusal::NoObservation, own_pid()).await?;
    assert!(matches!(
        error,
        BarrierError::Release(ReleaseBarrierError::Recheck)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ready_from_another_process_than_the_main_pid_is_not_released() -> TestResult {
    let error = refused(Refusal::None, own_pid() + 1).await?;
    assert!(matches!(
        error,
        BarrierError::Release(ReleaseBarrierError::PidMismatch)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_launcher_is_cut_off_at_the_attempt_deadline() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    // Hold the unit's end open and send nothing.
    let _unit_end = barrier.take_unit_end()?;
    let started = Instant::now();
    let error = barrier.release(&active(attempt, 300)).await.err();
    assert!(started.elapsed() >= Duration::from_millis(250));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(matches!(
        error,
        Some(BarrierError::Release(ReleaseBarrierError::ReadyUnavailable))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_unit_identity_is_refused() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    barrier.identity.broken = true;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::Identity(_))));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attempt_past_its_deadline_is_not_released() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    let error = barrier
        .release(&ActiveAttempt::record(attempt, Instant::now()))
        .await
        .err();
    assert!(matches!(error, Some(BarrierError::Expired)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unobservable_launcher_is_refused() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, u32::MAX)?;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::LauncherIdentity)));
    Ok(())
}

#[tokio::test]
async fn a_current_thread_runtime_is_refused_without_panicking() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::RuntimeFlavor)));
    Ok(())
}

#[test]
fn no_runtime_at_all_is_refused() {
    assert!(matches!(
        require_multi_thread(),
        Err(BarrierError::RuntimeFlavor)
    ));
}

#[test]
fn the_unit_end_is_handed_over_once_and_the_invocation_carries_the_parameters() -> TestResult {
    let (mut barrier, _attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    assert_eq!(
        barrier.launcher_invocation()?,
        LauncherInvocation::from_parameters(&barrier.parameters)?
    );
    assert_eq!(barrier.parameters.adapter_path, "/usr/bin/adapter");
    assert_eq!(barrier.parameters.arguments, ["--check"]);
    assert_eq!(barrier.parameters.sim1_digest, [0x51; 32]);
    assert!(barrier.take_unit_end().is_ok());
    assert!(matches!(
        barrier.take_unit_end(),
        Err(BarrierError::UnitEndTaken)
    ));
    Ok(())
}

#[test]
fn the_expected_layout_depends_on_the_mode() -> TestResult {
    let local = layout_digest(SandboxExecutionMode::Local)?;
    let air_gapped = layout_digest(SandboxExecutionMode::AirGapped)?;
    assert_ne!(local, air_gapped);
    // The mode is part of the FDL1 record, so even equal layouts differ by mode.
    assert_ne!(air_gapped, layout_digest(SandboxExecutionMode::Fork)?);
    Ok(())
}

#[test]
fn a_local_barrier_expects_the_proxy_as_fd3_and_the_release_channel_as_fd4() -> TestResult {
    let (barrier, _attempt) = barrier_for(SandboxExecutionMode::Local, Refusal::None, 1)?;
    let layout = [
        FdLayoutEntry {
            fd_number: 3,
            role: FdRole::HostService,
        },
        FdLayoutEntry {
            fd_number: 4,
            role: FdRole::Release,
        },
    ];
    let expected = fdl1_digest(SandboxExecutionMode::Local, &layout)?;
    assert_eq!(barrier.parameters.expected_fdl1_digest, expected);
    Ok(())
}

#[test]
fn a_nonce_is_fresh_and_nonzero() -> TestResult {
    let first = fresh_nonce()?;
    let second = fresh_nonce()?;
    assert_ne!(first, second);
    assert_ne!(first, [0; 32]);
    Ok(())
}

#[test]
fn the_launcher_executable_is_observed_by_mount_and_inode() -> TestResult {
    let observed = observe_executable(own_pid())?;
    let metadata = std::fs::metadata("/proc/self/exe")?;
    assert_eq!(
        observed.inode,
        std::os::unix::fs::MetadataExt::ino(&metadata)
    );
    assert_ne!(observed.mount_id, 0);
    assert!(matches!(
        observe_executable(u32::MAX),
        Err(BarrierError::LauncherIdentity)
    ));
    Ok(())
}

#[test]
fn the_release_window_is_the_time_left_on_the_monotonic_clock() -> TestResult {
    let before = monotonic_ns();
    let (remaining, absolute) = release_window(Instant::now() + Duration::from_secs(20))?;
    assert!(remaining <= Duration::from_secs(20));
    assert!(remaining > Duration::from_secs(19));
    assert!(absolute >= before + 19 * NANOSECONDS_PER_SECOND);
    assert!(absolute <= monotonic_ns() + 20 * NANOSECONDS_PER_SECOND);
    assert!(matches!(
        release_window(Instant::now()),
        Err(BarrierError::Expired)
    ));
    Ok(())
}
