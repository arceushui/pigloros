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
//! 2. bounds the `ReadyV1` receive with a socket timeout set to the time left
//!    before the attempt deadline, so a silent launcher cannot hold the
//!    provider; and
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
    error::Error,
    fs::File,
    future::Future,
    io::{self, Read},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use pos_reference::{
    provider_admission::AdmittedAuthority,
    sandbox_provider_protocol::{
        fdl1_digest, ExecutionRelease, FdIdentity, FdLayoutEntry, FdRole, LaunchParameters,
        SandboxExecutionMode, SandboxProviderProtocolError,
    },
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

/// The last-moment recheck before `ReleaseV1` (ADR-069: current RVS1, epochs,
/// cancellation, mount identity and observations).
///
/// `root` is the caller's `|| root.recheck(&directory, &entry)`: it rechecks
/// current authority, the control floor and the attached mount. The authority
/// heads bound into the release are the admitted ones, which that recheck
/// just confirmed.
pub struct AuthorityCheck<R, O> {
    authority: AdmittedAuthority,
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
    /// Bind the admitted `authority`, the root recheck, the selector-derived
    /// expected readback digest, the observed readback source and the
    /// cancellation flag the attempt lifecycle sets.
    #[must_use]
    pub const fn new(
        authority: AdmittedAuthority,
        root: R,
        expected_readback_digest: [u8; 32],
        observed: O,
        cancelled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            authority,
            root,
            expected_readback_digest,
            observed,
            cancelled,
        }
    }

    fn binding(&self, deadline_monotonic_ns: u64) -> Result<ReleaseBinding, ReleaseBarrierError> {
        (self.root)()
            .map_err(|_| ReleaseBarrierError::Recheck)
            .and_then(|_checked| {
                if self.cancelled.load(Ordering::SeqCst) {
                    Err(ReleaseBarrierError::Recheck)
                } else {
                    self.observed
                        .observed_digest()
                        .map_err(|_| ReleaseBarrierError::Recheck)
                }
            })
            .map(|observed_readback_digest| ReleaseBinding {
                trs1_digest: self.authority.trs1_digest,
                rvs1_digest: self.authority.rvs1_digest,
                apt1_digest: self.authority.apt1_digest,
                trust_epoch: self.authority.trust_epoch,
                revocation_epoch: self.authority.revocation_epoch,
                policy_epoch: self.authority.policy_epoch,
                expected_readback_digest: self.expected_readback_digest,
                observed_readback_digest,
                deadline_monotonic_ns,
            })
    }
}

/// An [`AuthorityCheck`] with the release deadline of this attempt.
struct Bounded<'a, R, O> {
    check: &'a AuthorityCheck<R, O>,
    deadline_monotonic_ns: u64,
}

impl<R, O> ReleaseRecheck for Bounded<'_, R, O>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
{
    fn recheck(&self) -> Result<ReleaseBinding, ReleaseBarrierError> {
        self.check.binding(self.deadline_monotonic_ns)
    }
}

/// Evidence the composition root already holds about the launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierEvidence {
    /// The admitted BLAKE3 digest of the launcher binary (SPM1/APT1-bound).
    pub launcher_digest: [u8; 32],
    /// The adapter's mount ID and inode, observed beneath the verified root.
    pub adapter_identity: FdIdentity,
}

/// Why the barrier could not be built or could not release.
#[derive(Debug, thiserror::Error)]
pub enum BarrierError {
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
}

/// The production [`LaunchBarrier`].
pub struct ProviderReleaseBarrier<S, I, R, O> {
    provider_end: std::os::fd::OwnedFd,
    unit_end: Option<OwnedFd>,
    parameters: LaunchParameters,
    evidence: BarrierEvidence,
    adapter_digest: [u8; 32],
    signer: S,
    identity: I,
    check: AuthorityCheck<R, O>,
    sent: Option<ExecutionRelease>,
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
        mode: SandboxExecutionMode,
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
        .map_err(|errno| BarrierError::Channel(io::Error::from(errno)))?;
        let parameters = layout_digest(mode)
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
            provider_end,
            unit_end: Some(OwnedFd::from(unit_end)),
            parameters,
            evidence,
            adapter_digest: attempt.executable_digest(),
            signer,
            identity,
            check,
            sent: None,
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
    let mut nonce = [0_u8; 32];
    File::open(source)?.read_exact(&mut nonce)?;
    Ok(nonce)
}

/// The mount ID and inode of `/proc/<pid>/exe`, as `statx` reports them.
fn observe_executable(pid: u32) -> Result<FdIdentity, BarrierError> {
    statx(
        CWD,
        format!("/proc/{pid}/exe").as_str(),
        AtFlags::empty(),
        StatxFlags::INO | StatxFlags::MNT_ID,
    )
    .ok()
    .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
    .map(|stat| FdIdentity {
        mount_id: stat.stx_mnt_id,
        inode: stat.stx_ino,
    })
    .ok_or(BarrierError::LauncherIdentity)
}

/// The time left before `deadline` and the absolute `CLOCK_MONOTONIC`
/// nanosecond value it corresponds to.
fn release_window(deadline: Instant) -> Result<(Duration, u64), BarrierError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(BarrierError::Expired)?;
    let now = clock_gettime(ClockId::Monotonic);
    let nanoseconds_per_second = i128::from(NANOSECONDS_PER_SECOND);
    let absolute = i128::from(now.tv_sec) * nanoseconds_per_second
        + i128::from(now.tv_nsec)
        + i128::from(remaining.as_secs()) * nanoseconds_per_second
        + i128::from(remaining.subsec_nanos());
    u64::try_from(absolute)
        .ok()
        .map(|absolute| (remaining, absolute))
        .ok_or(BarrierError::Expired)
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

impl<S, I, R, O> ProviderReleaseBarrier<S, I, R, O>
where
    S: ReleaseSigner + Send + Sync,
    I: UnitIdentitySource + Send + Sync,
    R: Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync,
    O: ObservedReadback + Send + Sync,
{
    async fn release_inner(&mut self, attempt: &ActiveAttempt) -> Result<(), BarrierError> {
        require_multi_thread()?;
        let main_pid = self
            .identity
            .main_pid(attempt.unit_name())
            .await
            .map_err(|error| BarrierError::Identity(Box::new(error)))?;
        let invocation = self
            .identity
            .invocation_id(attempt.unit_name())
            .await
            .map_err(|error| BarrierError::Identity(Box::new(error)))?;
        let expected = self.expected(invocation, observe_executable(main_pid)?);
        let (remaining, deadline_monotonic_ns) = release_window(attempt.deadline())?;
        set_socket_timeout(&self.provider_end, Timeout::Recv, Some(remaining))
            .map_err(|errno| BarrierError::Timeout(io::Error::from(errno)))?;
        let bounded = Bounded {
            check: &self.check,
            deadline_monotonic_ns,
        };
        let provider_end = &self.provider_end;
        let signer = &self.signer;
        let release = tokio::task::block_in_place(|| {
            release_after_ready(provider_end, main_pid, &expected, &bounded, signer)
        })?;
        self.sent = Some(release);
        Ok(())
    }

    const fn expected(&self, invocation: [u8; 16], launcher: FdIdentity) -> ExpectedLauncherReady {
        ExpectedLauncherReady {
            attempt_id: self.parameters.attempt_id,
            nonce: self.parameters.nonce,
            launch_instance_id: invocation,
            launcher_digest: self.evidence.launcher_digest,
            launcher_identity: launcher,
            sim1_digest: self.parameters.sim1_digest,
            adapter_digest: self.adapter_digest,
            adapter_identity: self.evidence.adapter_identity,
            launch_parameter_digest: self.parameters.digest,
            expected_fdl1_digest: self.parameters.expected_fdl1_digest,
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

    fn launcher_invocation(&self) -> Result<LauncherInvocation, BarrierError> {
        LauncherInvocation::from_parameters(&self.parameters).map_err(BarrierError::Parameters)
    }

    fn take_unit_end(&mut self) -> Result<OwnedFd, BarrierError> {
        self.unit_end.take().ok_or(BarrierError::UnitEndTaken)
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
