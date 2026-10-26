//! The production launcher barrier (ADR-069 "Trusted launcher and trust
//! binding" and "Requested state, observed state, and release barrier", #441).
//!
//! [`ProviderReleaseBarrier`] implements the [`LaunchBarrier`] port over
//! [`release_after_ready`]. Before the unit starts it builds the LPV1 launch
//! parameters (attempt, single-use nonce, SIM1, adapter path and arguments,
//! expected FDL1 digest) and the root-created `SOCK_SEQPACKET` release
//! channel. After the unit started and was verified it:
//!
//! 1. reads the unit's current `MainPID` and `InvocationID` fresh from the
//!    manager ([`UnitIdentitySource`]) and observes `/proc/<MainPID>/exe`
//!    itself, so the launcher's claims are compared with the provider's own
//!    observations, not with the launcher's word;
//! 2. bounds the `ReadyV1` receive and the `ReleaseV1` send with socket
//!    timeouts set to the time left before the attempt deadline, so a silent
//!    launcher cannot hold the provider; and
//! 3. runs the blocking receive, the recheck and the signed `ReleaseV1`
//!    send with [`tokio::task::block_in_place`], which exists only on a
//!    multi-thread runtime. A current-thread runtime is refused up front
//!    ([`BarrierError::RuntimeFlavor`]), never panicked into (owner decision
//!    Q9.16).
//!
//! [`AuthorityCheck`] is the last-moment recheck: the caller's root recheck
//! (current authority, control floor and attached mount identity), the
//! cancellation flag, and the observed readback-set digest, which #443 owns
//! behind [`ObservedReadback`].

use std::{
    cell::RefCell,
    error::Error,
    fs::File,
    future::Future,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use pos_reference::sandbox_provider_protocol::{
    blake3_digest_of, fdl1_digest, ExecutionRelease, FdIdentity, FdLayoutEntry, FdRole,
    LaunchParameters, SandboxExecutionMode, SandboxProviderProtocolError,
};
use rustix::{
    fs::{statx, AtFlags, StatxFlags, CWD},
    net::{
        socketpair,
        sockopt::{set_socket_timeout, Timeout},
        AddressFamily, SocketFlags, SocketType,
    },
    time::{clock_gettime, ClockId},
};
use zvariant::OwnedFd;

use crate::{
    release_after_ready, ActiveAttempt, AdmittedAttempt, CheckedRoot, ExpectedLauncherReady,
    ImageActivationError, LaunchBarrier, LauncherInvocation, ReleaseBarrierError, ReleaseBinding,
    ReleaseRecheck, ReleaseSigner, TransientServiceUnitName,
};

const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;
const HOST_SERVICE_FD: u64 = 3;
const LOCAL_RELEASE_FD: u64 = 4;
const OTHER_RELEASE_FD: u64 = 3;

/// The unit identity the manager reports, read fresh each time.
pub trait UnitIdentitySource {
    /// The source's failure type.
    type Error: Error + Send + Sync + 'static;

    /// The unit's current `MainPID`.
    fn main_pid(
        &self,
        unit_name: &TransientServiceUnitName,
    ) -> impl Future<Output = Result<u32, Self::Error>> + Send;

    /// The 16 bytes of the unit's current `InvocationID`.
    fn invocation_id(
        &self,
        unit_name: &TransientServiceUnitName,
    ) -> impl Future<Output = Result<[u8; 16], Self::Error>> + Send;
}

/// The observed readback-set digest that `ReleaseV1` binds.
///
/// The kernel-observation evidence behind it, and its digest, are #443's; the
/// provider supplies the implementation when that evidence exists.
pub trait ObservedReadback {
    /// The digest of the observed readback set, or why there is none.
    ///
    /// # Errors
    /// Returns [`ObservedReadbackUnavailable`] when no observation exists.
    fn observed_digest(&self) -> Result<[u8; 32], ObservedReadbackUnavailable>;
}

/// No observed readback set exists, so nothing may be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the observed readback set is unavailable")]
pub struct ObservedReadbackUnavailable;

/// Why the last-moment recheck refused the release. The release barrier only
/// reports that it refused; this keeps the cause for the attempt lifecycle
/// (#442) and the classifier (#443).
#[derive(Debug, thiserror::Error)]
pub enum RecheckRefusal {
    /// The verified root, current authority or the control floor no longer
    /// holds.
    #[error("the verified root could not be rechecked")]
    Root(#[source] ImageActivationError),
    /// The attempt was cancelled.
    #[error("the attempt was cancelled")]
    Cancelled,
    /// No observed readback set exists.
    #[error("no observed readback set exists")]
    Observation(#[source] ObservedReadbackUnavailable),
    /// The manager's identity of the unit could not be read again.
    #[error("the unit identity could not be read again")]
    Identity(#[source] Box<dyn Error + Send + Sync>),
    /// The attempt deadline passed while the unit identity was read again.
    #[error("the attempt deadline passed during the identity recheck")]
    Expired,
    /// The unit's `MainPID`, `InvocationID` or launcher executable changed
    /// after `ReadyV1` was verified against them.
    #[error("the unit identity changed after ReadyV1")]
    UnitChanged,
}

/// The last-moment recheck before `ReleaseV1` (ADR-069: current RVS1, epochs,
/// cancellation, mount identity and observations).
///
/// `root` is the caller's `|| root.recheck(&directory, &entry)`: it rechecks
/// current authority, the control floor and the attached mount. Its returned
/// proof must retain the barrier's complete admitted attempt before any
/// authority heads can be bound into the release.
pub struct AuthorityCheck<R, O> {
    root: R,
    expected_readback_digest: [u8; 32],
    observed: O,
    cancelled: Arc<AtomicBool>,
}

impl<R, O> AuthorityCheck<R, O>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
{
    /// Bind the root recheck, the selector-derived expected readback digest,
    /// the observed readback source and the cancellation flag the attempt
    /// lifecycle sets. The authority heads bound into the release are the
    /// admitted attempt's, taken by the barrier.
    #[must_use]
    pub const fn new(
        root: R,
        expected_readback_digest: [u8; 32],
        observed: O,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            root,
            expected_readback_digest,
            observed,
            cancelled,
        }
    }

    fn binding(
        &self,
        admitted: &AdmittedAttempt,
        deadline_monotonic_ns: u64,
    ) -> Result<ReleaseBinding, RecheckRefusal> {
        let checked = (self.root)().map_err(RecheckRefusal::Root)?;
        if !checked.matches_attempt(admitted) {
            return Err(RecheckRefusal::Root(ImageActivationError::EvidenceMismatch));
        }
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(RecheckRefusal::Cancelled);
        }
        let observed_readback_digest = self
            .observed
            .observed_digest()
            .map_err(RecheckRefusal::Observation)?;
        let authority = admitted.authority();
        Ok(ReleaseBinding {
            trs1_digest: authority.trs1_digest,
            rvs1_digest: authority.rvs1_digest,
            apt1_digest: authority.apt1_digest,
            trust_epoch: authority.trust_epoch,
            revocation_epoch: authority.revocation_epoch,
            policy_epoch: authority.policy_epoch,
            expected_readback_digest: self.expected_readback_digest,
            observed_readback_digest,
            deadline_monotonic_ns,
        })
    }
}

/// What the unit looked like when `ReadyV1` was verified against it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnitSnapshot {
    main_pid: u32,
    invocation: [u8; 16],
    launcher: FdIdentity,
}

/// An [`AuthorityCheck`] with the release deadline of this attempt, and the
/// unit identity it must still match when the recheck runs.
struct Bounded<'a, R, O, I> {
    check: &'a AuthorityCheck<R, O>,
    admitted: &'a AdmittedAttempt,
    deadline_monotonic_ns: u64,
    deadline: Instant,
    identity: &'a I,
    unit_name: &'a TransientServiceUnitName,
    snapshot: UnitSnapshot,
    launcher: &'a HeldLauncher,
    refusal: RefCell<Option<RecheckRefusal>>,
}

impl<R, O, I> Bounded<'_, R, O, I>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
    I: UnitIdentitySource,
{
    /// Read the unit identity again, as the last step before signing. Runs
    /// under `block_in_place` on a multi-thread runtime.
    fn unit_unchanged(&self) -> Result<(), RecheckRefusal> {
        let handle = tokio::runtime::Handle::current();
        let main_pid = self.read_again(&handle, self.identity.main_pid(self.unit_name))?;
        let invocation = self.read_again(&handle, self.identity.invocation_id(self.unit_name))?;
        let launcher = observe_executable(main_pid).map_err(|_| RecheckRefusal::UnitChanged)?;
        let current = UnitSnapshot {
            main_pid,
            invocation,
            launcher,
        };
        if current == self.snapshot {
            Ok(())
        } else {
            Err(RecheckRefusal::UnitChanged)
        }
    }

    /// One identity read, cut off at the attempt deadline.
    fn read_again<T>(
        &self,
        handle: &tokio::runtime::Handle,
        read: impl Future<Output = Result<T, I::Error>>,
    ) -> Result<T, RecheckRefusal> {
        let limit = tokio::time::Instant::from_std(self.deadline);
        handle
            .block_on(tokio::time::timeout_at(limit, read))
            .map_err(|_| RecheckRefusal::Expired)?
            .map_err(|error| RecheckRefusal::Identity(Box::new(error)))
    }

    fn rechecked(&self) -> Result<ReleaseBinding, RecheckRefusal> {
        verify_launcher(&self.launcher.file, &self.launcher.facts)
            .map_err(|_| RecheckRefusal::UnitChanged)?;
        let binding = self
            .check
            .binding(self.admitted, self.deadline_monotonic_ns)?;
        // The identity is read last, so nothing slower than the read itself
        // separates it from the signing.
        self.unit_unchanged()?;
        remaining_until(self.deadline).map_err(|_| RecheckRefusal::Expired)?;
        Ok(binding)
    }
}

impl<R, O, I> ReleaseRecheck for Bounded<'_, R, O, I>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
    I: UnitIdentitySource,
{
    fn recheck(&self) -> Result<ReleaseBinding, ReleaseBarrierError> {
        self.rechecked().map_err(|refusal| {
            *self.refusal.borrow_mut() = Some(refusal);
            ReleaseBarrierError::Recheck
        })
    }
}

/// Evidence the composition root already holds about the launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierEvidence {
    /// The adapter's mount ID and inode, observed beneath the verified root.
    pub adapter_identity: FdIdentity,
}

/// Why the barrier could not be built or could not release.
#[derive(Debug, thiserror::Error)]
pub enum BarrierError {
    /// The barrier and active job do not share the exact admitted context.
    #[error("the release barrier belongs to another admitted attempt")]
    AttemptMismatch,
    /// The descriptor layout or launch parameters are not valid records.
    #[error("the launch parameters are invalid")]
    Parameters(#[source] SandboxProviderProtocolError),
    /// The release channel could not be created.
    #[error("the release channel could not be created")]
    Channel(#[source] io::Error),
    /// The unit's end of the release channel was already handed over.
    #[error("the unit end of the release channel was already taken")]
    UnitEndTaken,
    /// The barrier needs a multi-thread Tokio runtime for its blocking receive.
    #[error("the release barrier needs a multi-thread runtime")]
    RuntimeFlavor,
    /// The manager's `MainPID` or `InvocationID` could not be read.
    #[error("the unit identity could not be read")]
    Identity(#[source] Box<dyn Error + Send + Sync>),
    /// `/proc/<MainPID>/exe` could not be observed.
    #[error("the launcher executable could not be observed")]
    LauncherIdentity,
    /// The attempt deadline passed before the release could start.
    #[error("the attempt deadline passed before the release")]
    Expired,
    /// The bounded receive could not be armed.
    #[error("the ReadyV1 receive could not be bounded")]
    Timeout(#[source] io::Error),
    /// `ReadyV1` was refused or `ReleaseV1` could not be sent.
    #[error(transparent)]
    Release(#[from] ReleaseBarrierError),
    /// The last-moment recheck refused the release, for this reason.
    #[error("the release was refused")]
    Refused(#[source] RecheckRefusal),
    /// A release was already attempted; `ReadyV1` and `ReleaseV1` are single
    /// use and never retried.
    #[error("a release was already attempted")]
    AlreadyAttempted,
}

/// The production [`LaunchBarrier`].
pub struct ProviderReleaseBarrier<S, I, R, O> {
    admitted: AdmittedAttempt,
    /// The provider's end of the channel (`std` type; the unit's end below is
    /// the `zvariant` type that D-Bus passes).
    provider_end: std::os::fd::OwnedFd,
    unit_end: Option<OwnedFd>,
    parameters: LaunchParameters,
    evidence: BarrierEvidence,
    adapter_digest: [u8; 32],
    signer: S,
    identity: I,
    check: AuthorityCheck<R, O>,
    sent: Option<ExecutionRelease>,
    attempted: bool,
}

impl<S, I, R, O> ProviderReleaseBarrier<S, I, R, O> {
    /// Build the LPV1 parameters and the release channel for `attempt`.
    ///
    /// `nonce` is the single-use 32-byte nonce, from [`fresh_nonce`].
    ///
    /// # Errors
    /// Rejects an invalid layout or launch parameters, and a release channel
    /// that cannot be created.
    pub fn new(
        attempt: &AdmittedAttempt,
        nonce: [u8; 32],
        evidence: BarrierEvidence,
        signer: S,
        identity: I,
        check: AuthorityCheck<R, O>,
    ) -> Result<Self, BarrierError> {
        let (provider_end, unit_end) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from)
        .map_err(BarrierError::Channel)?;
        let parameters = layout_digest(attempt.mode())
            .and_then(|layout| {
                LaunchParameters::new(
                    attempt.attempt_id(),
                    nonce,
                    attempt.sim1_digest(),
                    attempt.executable_path().to_owned(),
                    attempt.arguments().to_vec(),
                    layout,
                )
            })
            .map_err(BarrierError::Parameters)?;
        Ok(Self {
            admitted: attempt.clone(),
            provider_end,
            unit_end: Some(OwnedFd::from(unit_end)),
            parameters,
            evidence,
            adapter_digest: attempt.executable_digest(),
            signer,
            identity,
            check,
            sent: None,
            attempted: false,
        })
    }

    /// The `ReleaseV1` that was sent, for durable evidence (#443).
    #[must_use]
    pub const fn sent_release(&self) -> Option<&ExecutionRelease> {
        self.sent.as_ref()
    }
}

/// The FDL1 digest of the descriptor layout the mode expects: Local passes the
/// proxy as FD 3 and the release channel as FD 4; every other mode only the
/// release channel as FD 3.
fn layout_digest(mode: SandboxExecutionMode) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let entries = if mode == SandboxExecutionMode::Local {
        vec![
            FdLayoutEntry {
                fd_number: HOST_SERVICE_FD,
                role: FdRole::HostService,
            },
            FdLayoutEntry {
                fd_number: LOCAL_RELEASE_FD,
                role: FdRole::Release,
            },
        ]
    } else {
        vec![FdLayoutEntry {
            fd_number: OTHER_RELEASE_FD,
            role: FdRole::Release,
        }]
    };
    fdl1_digest(mode, &entries)
}

/// 32 random bytes for a single-use nonce.
///
/// # Errors
/// Returns the operating system's error if it cannot supply them.
pub fn fresh_nonce() -> io::Result<[u8; 32]> {
    nonce_from(Path::new("/dev/urandom"))
}

fn nonce_from(source: &Path) -> io::Result<[u8; 32]> {
    let mut nonce = <[u8; 32]>::default();
    File::open(source)?.read_exact(&mut nonce)?;
    Ok(nonce)
}

/// The mount ID and inode of `/proc/<pid>/exe`, as `statx` reports them.
fn observe_executable(pid: u32) -> Result<FdIdentity, BarrierError> {
    statx(
        CWD,
        format!("/proc/{pid}/exe").as_str(),
        AtFlags::empty(),
        StatxFlags::INO.union(StatxFlags::MNT_ID),
    )
    .ok()
    .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
    .map(|stat| FdIdentity {
        mount_id: stat.stx_mnt_id,
        inode: stat.stx_ino,
    })
    .ok_or(BarrierError::LauncherIdentity)
}

struct HeldLauncher {
    file: File,
    identity: FdIdentity,
    facts: crate::LauncherFacts,
}

/// Identify the very descriptor opened from the running process.
/// Holding it through the handshake prevents a path/stat/hash substitution.
fn hold_launcher(pid: u32, facts: &crate::LauncherFacts) -> Result<HeldLauncher, BarrierError> {
    let file =
        File::open(format!("/proc/{pid}/exe")).map_err(|_| BarrierError::LauncherIdentity)?;
    verify_launcher_identity(&file, facts)?;
    let identity = statx(
        &file,
        "",
        AtFlags::EMPTY_PATH,
        StatxFlags::INO.union(StatxFlags::MNT_ID),
    )
    .ok()
    .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
    .map(|stat| FdIdentity {
        mount_id: stat.stx_mnt_id,
        inode: stat.stx_ino,
    })
    .ok_or(BarrierError::LauncherIdentity)?;
    Ok(HeldLauncher {
        file,
        identity,
        facts: facts.clone(),
    })
}

fn verify_launcher(file: &File, facts: &crate::LauncherFacts) -> Result<(), BarrierError> {
    verify_launcher_identity(file, facts)?;
    let digest = blake3_digest_of(file).map_err(|_| BarrierError::LauncherIdentity)?;
    if digest != facts.digest {
        return Err(BarrierError::LauncherIdentity);
    }
    Ok(())
}

fn verify_launcher_identity(file: &File, facts: &crate::LauncherFacts) -> Result<(), BarrierError> {
    let metadata = file
        .metadata()
        .map_err(|_| BarrierError::LauncherIdentity)?;
    if (metadata.dev(), metadata.ino()) != facts.identity || metadata.len() != facts.length {
        return Err(BarrierError::LauncherIdentity);
    }
    Ok(())
}

/// The time left before `deadline` and the absolute `CLOCK_MONOTONIC`
/// nanosecond value it corresponds to.
fn release_window(deadline: Instant) -> Result<(Duration, u64), BarrierError> {
    release_window_with(
        deadline,
        || {
            let now = clock_gettime(ClockId::Monotonic);
            (i128::from(now.tv_sec), i128::from(now.tv_nsec))
        },
        Instant::now,
    )
}

fn release_window_with(
    deadline: Instant,
    monotonic: impl FnOnce() -> (i128, i128),
    instant: impl FnOnce() -> Instant,
) -> Result<(Duration, u64), BarrierError> {
    // Sample the absolute clock FIRST. A later remaining-time sample can only
    // shorten the signed window; preemption can never extend it beyond D.
    let (seconds, nanoseconds) = monotonic();
    release_window_at(deadline, instant(), seconds, nanoseconds)
}

fn release_window_at(
    deadline: Instant,
    sampled: Instant,
    seconds: i128,
    nanoseconds: i128,
) -> Result<(Duration, u64), BarrierError> {
    let remaining = deadline
        .checked_duration_since(sampled)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(BarrierError::Expired)?;
    absolute_deadline_ns(seconds, nanoseconds, remaining)
        .map(|absolute| (remaining, absolute))
        .ok_or(BarrierError::Expired)
}

fn remaining_until(deadline: Instant) -> Result<Duration, BarrierError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(BarrierError::Expired)
}

/// `CLOCK_MONOTONIC` nanoseconds at `now` plus `remaining`, if it fits.
fn absolute_deadline_ns(
    now_seconds: i128,
    now_nanoseconds: i128,
    remaining: Duration,
) -> Option<u64> {
    let nanoseconds_per_second = i128::from(NANOSECONDS_PER_SECOND);
    let absolute = (now_seconds + i128::from(remaining.as_secs())) * nanoseconds_per_second
        + now_nanoseconds
        + i128::from(remaining.subsec_nanos());
    u64::try_from(absolute).ok()
}

/// One manager read, cut off at the attempt `deadline`.
async fn read_by<T, E>(
    deadline: Instant,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, BarrierError>
where
    E: Error + Send + Sync + 'static,
{
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), read)
        .await
        .map_err(|_| BarrierError::Expired)?
        .map_err(|error| BarrierError::Identity(Box::new(error)))
}

/// Bound both the `ReadyV1` receive and the `ReleaseV1` send by the time left.
fn bound_channel(channel: &std::os::fd::OwnedFd, deadline: Instant) -> Result<(), BarrierError> {
    [Timeout::Recv, Timeout::Send]
        .into_iter()
        .try_for_each(|direction| {
            remaining_until(deadline).and_then(|remaining| {
                set_socket_timeout(channel, direction, Some(remaining))
                    .map_err(|errno| BarrierError::Timeout(io::Error::from(errno)))
            })
        })
}

fn require_multi_thread() -> Result<(), BarrierError> {
    let multi_thread = tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi_thread {
        Ok(())
    } else {
        Err(BarrierError::RuntimeFlavor)
    }
}

/// The low-level signing port cannot supply its own admission authority.
/// RLS1 rejects a zero signature, so a mismatched ID or unverifiable signature
/// fails before the release packet can be serialized or sent.
struct AdmittedReleaseSigner<'a> {
    signer: &'a dyn ReleaseSigner,
    attempt: &'a AdmittedAttempt,
}

impl ReleaseSigner for AdmittedReleaseSigner<'_> {
    fn runtime_attestation_key_id(&self) -> &str {
        self.attempt.runtime_key_id()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        if self.signer.runtime_attestation_key_id() != self.attempt.runtime_key_id() {
            return [0; 64];
        }
        let signature = self.signer.sign(message);
        if self
            .attempt
            .runtime_key()
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .is_ok()
        {
            signature
        } else {
            [0; 64]
        }
    }
}

impl<S, I, R, O> ProviderReleaseBarrier<S, I, R, O>
where
    S: ReleaseSigner + Send + Sync,
    I: UnitIdentitySource + Send + Sync,
    R: Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync,
    O: ObservedReadback + Send + Sync,
{
    async fn release_inner(&mut self, attempt: &ActiveAttempt) -> Result<(), BarrierError> {
        require_multi_thread()?;
        self.require_attempt(attempt.admitted())?;
        if self.attempted {
            return Err(BarrierError::AlreadyAttempted);
        }
        let main_pid = read_by(
            attempt.deadline(),
            self.identity.main_pid(attempt.unit_name()),
        )
        .await?;
        let invocation = read_by(
            attempt.deadline(),
            self.identity.invocation_id(attempt.unit_name()),
        )
        .await?;
        let held_launcher =
            tokio::task::block_in_place(|| hold_launcher(main_pid, self.admitted.launcher()))?;
        let launcher = held_launcher.identity;
        let expected = self.expected(invocation, launcher);
        let (_, deadline_monotonic_ns) = release_window(attempt.deadline())?;
        // Nothing above consumes `ReadyV1`, so dropping the future before this
        // point leaves the barrier unused; from here the release is one-shot.
        self.attempted = true;
        let bounded = Bounded {
            check: &self.check,
            admitted: &self.admitted,
            deadline_monotonic_ns,
            deadline: attempt.deadline(),
            identity: &self.identity,
            unit_name: attempt.unit_name(),
            snapshot: UnitSnapshot {
                main_pid,
                invocation,
                launcher,
            },
            launcher: &held_launcher,
            refusal: RefCell::new(None),
        };
        let provider_end = &self.provider_end;
        let signer = AdmittedReleaseSigner {
            signer: &self.signer,
            attempt: &self.admitted,
        };
        let released = tokio::task::block_in_place(|| {
            bound_channel(provider_end, attempt.deadline())?;
            release_after_ready(provider_end, main_pid, &expected, &bounded, &signer)
                .map_err(BarrierError::Release)
        });
        let release = released
            .map_err(|error| bounded.refusal.take().map_or(error, BarrierError::Refused))?;
        self.sent = Some(release);
        remaining_until(attempt.deadline())?;
        Ok(())
    }

    const fn expected(&self, invocation: [u8; 16], launcher: FdIdentity) -> ExpectedLauncherReady {
        ExpectedLauncherReady {
            attempt_id: self.parameters.attempt_id,
            nonce: self.parameters.nonce,
            launch_instance_id: invocation,
            launcher_digest: self.admitted.launcher().digest,
            launcher_identity: launcher,
            sim1_digest: self.parameters.sim1_digest,
            adapter_digest: self.adapter_digest,
            adapter_identity: self.evidence.adapter_identity,
            launch_parameter_digest: self.parameters.digest,
            expected_fdl1_digest: self.parameters.expected_fdl1_digest,
        }
    }

    fn require_attempt(&self, attempt: &AdmittedAttempt) -> Result<(), BarrierError> {
        if &self.admitted == attempt {
            Ok(())
        } else {
            Err(BarrierError::AttemptMismatch)
        }
    }
}

impl<S, I, R, O> LaunchBarrier for ProviderReleaseBarrier<S, I, R, O>
where
    S: ReleaseSigner + Send + Sync,
    I: UnitIdentitySource + Send + Sync,
    R: Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync,
    O: ObservedReadback + Send + Sync,
{
    type Error = BarrierError;

    fn prepare(
        &mut self,
        attempt: &AdmittedAttempt,
    ) -> Result<(LauncherInvocation, OwnedFd), BarrierError> {
        // Called before the start, so a wrong runtime never starts a unit.
        require_multi_thread()?;
        self.require_attempt(attempt)?;
        let invocation = LauncherInvocation::from_parameters(&self.parameters)
            .map_err(BarrierError::Parameters)?;
        self.unit_end
            .take()
            .ok_or(BarrierError::UnitEndTaken)
            .map(|end| (invocation, end))
    }

    fn release(
        &mut self,
        attempt: &ActiveAttempt,
    ) -> impl Future<Output = Result<(), BarrierError>> + Send {
        self.release_inner(attempt)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
