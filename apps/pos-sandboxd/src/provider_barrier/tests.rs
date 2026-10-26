use std::{
    io::IoSlice,
    mem::MaybeUninit,
    os::{fd::OwnedFd as StdOwnedFd, unix::fs::PermissionsExt},
    sync::atomic::AtomicUsize,
    thread::{self, JoinHandle},
};

use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{LauncherReady, LauncherReadyFields};
use rustix::{
    net::{recv, sendmsg, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, UCred},
    process::{getgid, getpid, getuid},
};

use super::*;
use crate::test_fixtures::{authority, TestResult, ATTEMPT};

const KEY_ID: &str = crate::test_fixtures::RUNTIME_KEY_ID;
const EXPECTED_READBACK: [u8; 32] = [5; 32];
const OBSERVED_READBACK: [u8; 32] = [6; 32];
const INVOCATION: [u8; 16] = [0x12; 16];
const ADAPTER_IDENTITY: FdIdentity = FdIdentity {
    mount_id: 9,
    inode: 77,
};
const GENEROUS_MS: u64 = 30_000;

struct TestSigner {
    key: SigningKey,
    key_id: &'static str,
}

impl ReleaseSigner for TestSigner {
    fn runtime_attestation_key_id(&self) -> &str {
        self.key_id
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the unit identity is unavailable")]
struct IdentityDown;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Normal,
    MainPidDown,
    InvocationDown,
    /// The second `InvocationID` read differs from the first.
    InvocationDrifts,
    /// The second `InvocationID` read fails.
    InvocationBreaksAfterFirstRead,
    /// `MainPID` never answers.
    Hangs,
    /// The second `MainPID` read never answers.
    HangsAfterFirstRead,
    /// The second `MainPID` read names another process.
    MainPidDrifts,
}

struct TestIdentity {
    pid: u32,
    behaviour: Behaviour,
    invocation_reads: AtomicUsize,
    main_pid_reads: AtomicUsize,
}

impl TestIdentity {
    const fn new(pid: u32) -> Self {
        Self::behaving(pid, Behaviour::Normal)
    }

    fn main_pid_after(&self, reads: usize) -> Result<u32, IdentityDown> {
        match self.behaviour {
            Behaviour::MainPidDown => Err(IdentityDown),
            Behaviour::MainPidDrifts if reads > 0 => Ok(u32::MAX),
            _ => Ok(self.pid),
        }
    }

    fn main_pid_hangs(&self, reads: usize) -> bool {
        match self.behaviour {
            Behaviour::Hangs => true,
            Behaviour::HangsAfterFirstRead => reads > 0,
            _ => false,
        }
    }

    const fn behaving(pid: u32, behaviour: Behaviour) -> Self {
        Self {
            pid,
            behaviour,
            invocation_reads: AtomicUsize::new(0),
            main_pid_reads: AtomicUsize::new(0),
        }
    }
}

impl UnitIdentitySource for TestIdentity {
    type Error = IdentityDown;

    fn main_pid(
        &self,
        _unit_name: &TransientServiceUnitName,
    ) -> impl Future<Output = Result<u32, IdentityDown>> + Send {
        let reads = self.main_pid_reads.fetch_add(1, Ordering::SeqCst);
        let outcome = self.main_pid_after(reads);
        let hangs = self.main_pid_hangs(reads);
        async move {
            if hangs {
                std::future::pending::<()>().await;
            }
            outcome
        }
    }

    async fn invocation_id(
        &self,
        _unit_name: &TransientServiceUnitName,
    ) -> Result<[u8; 16], IdentityDown> {
        let reads = self.invocation_reads.fetch_add(1, Ordering::SeqCst);
        match self.behaviour {
            Behaviour::InvocationDown => Err(IdentityDown),
            Behaviour::InvocationBreaksAfterFirstRead if reads > 0 => Err(IdentityDown),
            Behaviour::InvocationDrifts if reads > 0 => Ok([0x13; 16]),
            _ => Ok(INVOCATION),
        }
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
type TestBarrier<S = TestSigner> = ProviderReleaseBarrier<S, TestIdentity, RootCheck, TestObserved>;

fn root_check(refusal: Refusal, attempt: &AdmittedAttempt) -> RootCheck {
    if matches!(refusal, Refusal::RootFails) {
        Box::new(|| Err(ImageActivationError::EvidenceMismatch))
    } else {
        let attempt = attempt.clone();
        Box::new(move || Ok(crate::test_fixtures::checked_root(&attempt)))
    }
}

fn test_signer() -> TestSigner {
    TestSigner {
        key: SigningKey::from_bytes(&crate::test_fixtures::RUNTIME_SEED),
        key_id: KEY_ID,
    }
}

/// A barrier for `attempt` whose manager reports `claimed_pid`.
fn barrier_with(
    attempt: &AdmittedAttempt,
    refusal: Refusal,
    identity: TestIdentity,
) -> TestResult<TestBarrier> {
    let observed = (!matches!(refusal, Refusal::NoObservation)).then_some(OBSERVED_READBACK);
    let cancelled = Arc::new(AtomicBool::new(matches!(refusal, Refusal::Cancelled)));
    let check = AuthorityCheck::new(
        root_check(refusal, attempt),
        EXPECTED_READBACK,
        TestObserved(observed),
        cancelled,
    );
    Ok(ProviderReleaseBarrier::new(
        attempt,
        fresh_nonce()?,
        BarrierEvidence {
            adapter_identity: ADAPTER_IDENTITY,
        },
        test_signer(),
        identity,
        check,
    )?)
}

/// A barrier whose manager reports `claimed_pid`, plus its admitted attempt.
fn barrier_for(
    mode: SandboxExecutionMode,
    refusal: Refusal,
    claimed_pid: u32,
) -> TestResult<(TestBarrier, AdmittedAttempt)> {
    let attempt = AdmittedAttempt::for_test(ATTEMPT, authority(), mode)?;
    let barrier = barrier_with(&attempt, refusal, TestIdentity::new(claimed_pid))?;
    Ok((barrier, attempt))
}

fn own_pid() -> u32 {
    std::process::id()
}

fn ready_for<S>(barrier: &TestBarrier<S>) -> TestResult<LauncherReady> {
    let parameters = &barrier.parameters;
    Ok(LauncherReady::new(LauncherReadyFields {
        attempt_id: parameters.attempt_id,
        nonce: parameters.nonce,
        launch_instance_id: INVOCATION,
        launcher_digest: barrier.admitted.launcher().digest,
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
fn launcher<S: ReleaseSigner + Send + Sync>(
    barrier: &mut TestBarrier<S>,
) -> TestResult<JoinHandle<Option<ExecutionRelease>>> {
    let attempt = barrier.admitted.clone();
    let unit_end = StdOwnedFd::from(barrier.prepare(&attempt)?.1);
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
    release.verify_signature(barrier.admitted.runtime_key())?;
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

/// The kernel thread id of a thread that stays alive until the sender drops.
fn parked_thread_id() -> TestResult<(u32, std::sync::mpsc::Sender<()>)> {
    let (alive, parked) = std::sync::mpsc::channel::<()>();
    let (reported, tid) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let link = std::fs::read_link("/proc/thread-self").ok();
        reported.send(link).ok();
        parked.recv().ok();
    });
    let link = tid.recv()?.ok_or("no /proc/thread-self")?;
    let tid = link
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("no thread id")?
        .parse()?;
    Ok((tid, alive))
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
    check_channel_bounds(&barrier)
}

/// Both directions of the channel were bounded by the time left.
fn check_channel_bounds(barrier: &TestBarrier) -> TestResult {
    for direction in [Timeout::Recv, Timeout::Send] {
        let bound = rustix::net::sockopt::socket_timeout(&barrier.provider_end, direction)?;
        assert!(bound.is_some_and(|limit| limit <= Duration::from_millis(GENEROUS_MS)));
    }
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
        BarrierError::Refused(RecheckRefusal::Cancelled)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_root_recheck_is_not_released() -> TestResult {
    let error = refused(Refusal::RootFails, own_pid()).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::Root(_))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_observed_readback_is_not_released() -> TestResult {
    let error = refused(Refusal::NoObservation, own_pid()).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::Observation(_))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ready_from_another_process_than_the_main_pid_is_not_released() -> TestResult {
    // A live thread id: `/proc/<tid>/exe` is observable, but the launcher
    // (this process) is not that id, so the kernel-supplied pid differs.
    let (tid, release_thread) = parked_thread_id()?;
    let error = refused(Refusal::None, tid).await?;
    drop(release_thread);
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
    let _unit_end = barrier.prepare(&attempt)?.1;
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
    barrier.identity.behaviour = Behaviour::MainPidDown;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::Identity(_))));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unit_identity_is_read_after_the_other_rechecks() -> TestResult {
    // Both the attempt is cancelled and the invocation drifts: the cancellation
    // is reported because the identity is read last.
    let attempt = AdmittedAttempt::for_test(ATTEMPT, authority(), SandboxExecutionMode::AirGapped)?;
    let identity = TestIdentity::behaving(own_pid(), Behaviour::InvocationDrifts);
    let mut barrier = barrier_with(&attempt, Refusal::Cancelled, identity)?;
    let launcher = launcher(&mut barrier)?;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(
        error,
        Some(BarrierError::Refused(RecheckRefusal::Cancelled))
    ));
    drop(barrier);
    assert_eq!(launcher.join().map_err(|_| "launcher thread")?, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_manager_that_never_answers_is_cut_off_at_the_attempt_deadline() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    barrier.identity.behaviour = Behaviour::Hangs;
    let started = Instant::now();
    let error = barrier.release(&active(attempt, 300)).await.err();
    assert!(matches!(error, Some(BarrierError::Expired)));
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(barrier.sent_release().is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_invocation_id_is_refused() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    barrier.identity.behaviour = Behaviour::InvocationDown;
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::Identity(_))));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_channel_that_takes_no_timeout_is_refused() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    barrier.provider_end = StdOwnedFd::from(std::fs::File::open("/dev/null")?);
    let error = barrier.release(&active(attempt, GENEROUS_MS)).await.err();
    assert!(matches!(error, Some(BarrierError::Timeout(_))));
    Ok(())
}

#[test]
fn launch_parameters_that_do_not_fit_are_refused() -> TestResult {
    let attempt = AdmittedAttempt::for_test(ATTEMPT, authority(), SandboxExecutionMode::AirGapped)?
        .running("a".repeat(1 << 20));
    let barrier = barrier_with(&attempt, Refusal::None, TestIdentity::new(own_pid()));
    assert!(matches!(
        barrier
            .err()
            .and_then(|error| error.downcast::<BarrierError>().ok())
            .as_deref(),
        Some(BarrierError::Parameters(_))
    ));
    Ok(())
}

#[test]
fn a_nonce_source_that_cannot_supply_32_bytes_is_refused() {
    assert!(nonce_from(Path::new("/dev/null")).is_err());
    assert!(nonce_from(Path::new("/nonexistent/urandom")).is_err());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unit_end_is_handed_over_once_and_the_invocation_carries_the_parameters() -> TestResult
{
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    assert_eq!(
        barrier.prepare(&attempt)?.0,
        LauncherInvocation::from_parameters(&barrier.parameters)?
    );
    assert_eq!(barrier.parameters.adapter_path, "/usr/bin/adapter");
    assert_eq!(barrier.adapter_digest, [0x61; 32]);
    assert_eq!(barrier.parameters.arguments, ["--check"]);
    assert_eq!(barrier.parameters.sim1_digest, [0x51; 32]);
    assert!(matches!(
        barrier.prepare(&attempt),
        Err(BarrierError::UnitEndTaken)
    ));
    Ok(())
}

#[tokio::test]
async fn a_current_thread_runtime_is_refused_before_the_unit_would_start() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    assert!(matches!(
        barrier.prepare(&attempt),
        Err(BarrierError::RuntimeFlavor)
    ));
    Ok(())
}

/// Release against a unit whose identity misbehaves after `ReadyV1`; the
/// launcher is never answered.
async fn refused_with(behaviour: Behaviour, milliseconds: u64) -> TestResult<BarrierError> {
    let attempt = AdmittedAttempt::for_test(ATTEMPT, authority(), SandboxExecutionMode::AirGapped)?;
    let identity = TestIdentity::behaving(own_pid(), behaviour);
    let mut barrier = barrier_with(&attempt, Refusal::None, identity)?;
    let launcher = launcher(&mut barrier)?;
    let error = barrier.release(&active(attempt, milliseconds)).await.err();
    drop(barrier);
    assert_eq!(launcher.join().map_err(|_| "launcher thread")?, None);
    error.ok_or_else(|| "the release was not refused".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_whose_invocation_changes_after_ready_is_not_released() -> TestResult {
    let error = refused_with(Behaviour::InvocationDrifts, GENEROUS_MS).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::UnitChanged)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_unit_whose_main_pid_changes_after_ready_is_not_released() -> TestResult {
    let error = refused_with(Behaviour::MainPidDrifts, GENEROUS_MS).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::UnitChanged)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_read_that_outlasts_the_deadline_is_not_released() -> TestResult {
    let error = refused_with(Behaviour::HangsAfterFirstRead, 3_000).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::Expired)
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_identity_after_ready_is_not_released() -> TestResult {
    let error = refused_with(Behaviour::InvocationBreaksAfterFirstRead, GENEROUS_MS).await?;
    assert!(matches!(
        error,
        BarrierError::Refused(RecheckRefusal::Identity(_))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_release_is_refused_after_the_first() -> TestResult {
    let (mut barrier, attempt) = barrier_for(
        SandboxExecutionMode::AirGapped,
        Refusal::Cancelled,
        own_pid(),
    )?;
    let launcher = launcher(&mut barrier)?;
    let attempt = active(attempt, GENEROUS_MS);
    assert!(barrier.release(&attempt).await.is_err());
    assert!(matches!(
        barrier.release(&attempt).await.err(),
        Some(BarrierError::AlreadyAttempted)
    ));
    drop(barrier);
    assert_eq!(launcher.join().map_err(|_| "launcher thread")?, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_release_leaves_the_barrier_usable() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    let attempt = active(attempt, GENEROUS_MS);
    barrier.identity.behaviour = Behaviour::Hangs;
    // The caller gives up while the manager does not answer.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), barrier.release(&attempt))
            .await
            .is_err()
    );
    assert!(barrier.sent_release().is_none());
    barrier.identity.behaviour = Behaviour::Normal;
    let launcher = launcher(&mut barrier)?;
    barrier.release(&attempt).await?;
    let received = launcher.join().map_err(|_| "launcher thread")?;
    check_release(&barrier, received.as_ref())
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
fn the_absolute_deadline_adds_every_component() {
    let remaining = Duration::new(2, 300);
    assert_eq!(absolute_deadline_ns(5, 250, remaining), Some(7_000_000_550));
    assert_eq!(absolute_deadline_ns(-1, 0, Duration::ZERO), None);
}

#[test]
fn clock_translation_never_extends_the_original_attempt_deadline() -> TestResult {
    let first = Instant::now();
    let deadline = first + Duration::from_secs(10);
    // The monotonic sample is 5s at `first`; sampling Instant 3s later must
    // shorten the signed absolute deadline, never move it from 15s to 18s.
    let order = RefCell::new(Vec::new());
    let (remaining, absolute) = release_window_with(
        deadline,
        || {
            order.borrow_mut().push("monotonic");
            (5, 0)
        },
        || {
            order.borrow_mut().push("instant");
            first + Duration::from_secs(3)
        },
    )?;
    assert_eq!(*order.borrow(), ["monotonic", "instant"]);
    assert_eq!(remaining, Duration::from_secs(7));
    assert_eq!(absolute, 12_000_000_000);
    assert!(matches!(
        release_window_at(deadline, deadline, 15, 0),
        Err(BarrierError::Expired)
    ));
    assert!(matches!(
        release_window_at(deadline, first, -100, 0),
        Err(BarrierError::Expired)
    ));
    assert!(matches!(remaining_until(first), Err(BarrierError::Expired)));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_barrier_rejects_a_different_valid_attempt_before_handoff_or_identity_read() -> TestResult
{
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    let mut other = AdmittedAttempt::for_test(
        crate::test_fixtures::OTHER,
        authority(),
        SandboxExecutionMode::AirGapped,
    )?;
    assert!(matches!(
        barrier.prepare(&other),
        Err(BarrierError::AttemptMismatch)
    ));
    assert!(matches!(
        barrier.release(&active(other.clone(), GENEROUS_MS)).await,
        Err(BarrierError::AttemptMismatch)
    ));
    assert_eq!(barrier.identity.main_pid_reads.load(Ordering::SeqCst), 0);
    // Even a reused attempt ID cannot substitute another admitted authority.
    let mut changed = authority();
    changed.policy_epoch += 1;
    other = AdmittedAttempt::for_test(ATTEMPT, changed, SandboxExecutionMode::AirGapped)?;
    assert!(matches!(
        barrier.prepare(&other),
        Err(BarrierError::AttemptMismatch)
    ));
    // Rejection consumed neither the release descriptor nor its single use.
    let launcher = launcher(&mut barrier)?;
    barrier.release(&active(attempt, GENEROUS_MS)).await?;
    assert!(launcher.join().map_err(|_| "launcher thread")?.is_some());
    Ok(())
}

#[test]
fn an_executable_must_match_the_admitted_inode_length_and_actual_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("launcher");
    std::fs::write(&path, b"admitted executable")?;
    let metadata = std::fs::metadata(&path)?;
    let facts = crate::LauncherFacts {
        path: path.to_string_lossy().into_owned(),
        digest: *blake3::hash(b"admitted executable").as_bytes(),
        length: metadata.len(),
        identity: (metadata.dev(), metadata.ino()),
    };
    verify_launcher(&File::open(&path)?, &facts)?;
    let mut wrong = facts.clone();
    wrong.identity.1 += 1;
    assert!(verify_launcher(&File::open(&path)?, &wrong).is_err());
    wrong = facts.clone();
    wrong.length += 1;
    assert!(verify_launcher(&File::open(&path)?, &wrong).is_err());
    wrong = facts;
    wrong.digest = [0x71; 32];
    assert!(verify_launcher(&File::open(&path)?, &wrong).is_err());
    // A descriptor whose bytes cannot be read must also fail closed.
    let unreadable = File::open(directory.path())?;
    let metadata = unreadable.metadata()?;
    wrong.identity = (metadata.dev(), metadata.ino());
    wrong.length = metadata.len();
    assert!(verify_launcher(&unreadable, &wrong).is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_substituted_running_launcher_cannot_self_assert_the_admitted_digest() -> TestResult {
    let (mut barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    // Keep the real MainPID/mount/inode but change the independently admitted
    // digest. A matching ReadyV1 claim must never replace a provider hash.
    barrier.admitted = barrier.admitted.clone().with_launcher_digest([0x71; 32]);
    let attempt = attempt.with_launcher_digest([0x71; 32]);
    barrier.check.root = root_check(Refusal::None, &attempt);
    let launcher = launcher(&mut barrier)?;
    assert!(matches!(
        barrier.release(&active(attempt, GENEROUS_MS)).await,
        Err(BarrierError::Refused(RecheckRefusal::UnitChanged))
    ));
    drop(barrier);
    assert!(launcher.join().map_err(|_| "launcher thread")?.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recheck_for_another_admitted_context_cannot_authorize_release() -> TestResult {
    let mut changed = authority();
    changed.policy_epoch += 1;
    let alternatives = [
        AdmittedAttempt::for_test(
            crate::test_fixtures::OTHER,
            authority(),
            SandboxExecutionMode::AirGapped,
        )?,
        AdmittedAttempt::for_test(ATTEMPT, changed, SandboxExecutionMode::AirGapped)?,
    ];
    for other in alternatives {
        let (mut barrier, attempt) =
            barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
        // The barrier, job and Ready all agree on A. Only the otherwise valid
        // recheck belongs to B, including the same-ID/different-authority case.
        barrier.check.root = root_check(Refusal::None, &other);
        let launcher = launcher(&mut barrier)?;
        assert!(matches!(
            barrier.release(&active(attempt, GENEROUS_MS)).await,
            Err(BarrierError::Refused(RecheckRefusal::Root(
                ImageActivationError::EvidenceMismatch
            )))
        ));
        assert!(barrier.sent_release().is_none());
        drop(barrier);
        assert!(launcher.join().map_err(|_| "launcher thread")?.is_none());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_safe_key_file_cannot_substitute_another_runtime_signing_identity() -> TestResult {
    for (key_id, seed) in [
        ("foreign-runtime-key", crate::test_fixtures::RUNTIME_SEED),
        (KEY_ID, [0x53; 32]),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("key");
        std::fs::write(&path, seed)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        let held = File::open(directory.path())?;
        let signer = crate::KeyFileReleaseSigner::open(
            &held,
            "key",
            held.metadata()?.uid(),
            key_id.to_owned(),
        )?;
        let (parts, attempt) =
            barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
        let mut barrier = ProviderReleaseBarrier::new(
            &attempt,
            fresh_nonce()?,
            parts.evidence,
            signer,
            parts.identity,
            parts.check,
        )?;
        let launcher = launcher(&mut barrier)?;
        assert!(matches!(
            barrier.release(&active(attempt, GENEROUS_MS)).await,
            Err(BarrierError::Release(ReleaseBarrierError::Sign(_)))
        ));
        assert!(barrier.sent_release().is_none());
        drop(barrier);
        assert!(launcher.join().map_err(|_| "launcher thread")?.is_none());
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recheck_resumed_after_the_original_deadline_cannot_release() -> TestResult {
    let (barrier, attempt) =
        barrier_for(SandboxExecutionMode::AirGapped, Refusal::None, own_pid())?;
    let held = hold_launcher(own_pid(), attempt.launcher())?;
    let bounded = Bounded {
        check: &barrier.check,
        admitted: &attempt,
        deadline_monotonic_ns: monotonic_ns(),
        deadline: Instant::now(),
        identity: &barrier.identity,
        unit_name: attempt.unit_name(),
        snapshot: UnitSnapshot {
            main_pid: own_pid(),
            invocation: INVOCATION,
            launcher: held.identity,
        },
        launcher: &held,
        refusal: RefCell::new(None),
    };
    // Model a valid Ready followed by provider preemption. Immediate manager
    // reads can complete even when Tokio's timeout is already due; the
    // original deadline must still forbid a release after the final recheck.
    let result = tokio::task::block_in_place(|| bounded.rechecked());
    assert!(matches!(result, Err(RecheckRefusal::Expired)));
    Ok(())
}
