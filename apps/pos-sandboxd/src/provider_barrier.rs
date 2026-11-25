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
//!    manager ([`UnitIdentitySource`]), observes `/proc/<MainPID>/exe`
//!    itself, and observes the adapter at its admitted path beneath the
//!    pidfd-anchored `/proc/<MainPID>/root` (owner decision 2026-11-21), so
//!    the launcher's claims are compared with the provider's own
//!    observations in the unit's mount namespace, not with the launcher's
//!    word;
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
//! cancellation flag, and the kernel observation behind [`ObservedReadback`].
//! Once `ReadyV1` is accepted the barrier observes the unit's kernel state
//! and freezes it as the attempt's KOE1, which binds the attempt's RQE1
//! (ADR-069 R9 §4.4); the recheck observes it again and releases only if both
//! observations are equal. The observed readback digest `ReleaseV1` binds is
//! that KOE1's self-digest, and the release is signed through the sealed
//! runtime-attestation signer, verified under the admitted key first.

use std::{
    cell::{Cell, RefCell},
    error::Error,
    fs::File,
    future::Future,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

use pos_reference::sandbox_provider_protocol::{
    blake3_digest_of, fdl1_digest, ExecutionRelease, FdIdentity, FdLayoutEntry, FdRole,
    LaunchParameters, SandboxExecutionMode, SandboxProviderProtocolError,
};
use rustix::{
    fs::{statx, AtFlags, StatxFlags, CWD},
    io::Errno,
    net::{
        socketpair,
        sockopt::{set_socket_timeout, Timeout},
        AddressFamily, SocketFlags, SocketType,
    },
    time::{clock_gettime, ClockId},
};
use zbus::OwnedFd;

use pos_reference::sandbox_provider_protocol::{BarrierFailure, KernelObservationEvidence};

use crate::{
    observation_evidence, release_after_ready, ActiveAttempt, AdmittedAttempt, AdmittedRuntimeKey,
    CancelSignal, CgroupView, CheckedRoot, ExpectedLauncherReady, ImageActivationError,
    KernelObservationError, LaunchBarrier, LauncherInvocation, NetworkReadback, ObservationContext,
    ObservedUnit, ReadbackError, ReleaseBarrierError, ReleaseBinding, ReleaseOutcome,
    ReleaseRecheck, RuntimeAttestationSigner, TransientServiceUnitName, UnitNetworkError,
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

/// The kernel observation behind the observed readback digest that
/// `ReleaseV1` binds (ADR-069 R9 §4.4).
///
/// The production implementation is [`crate::KernelObservedReadback`].
pub trait ObservedReadback {
    /// Observe the released unit now. `unit` reads the manager's `MainPID`
    /// and `InvocationID`; `context` is what the provider already holds.
    ///
    /// # Errors
    /// Returns [`ObservedReadbackUnavailable`] when no observation can be made.
    fn observe(
        &self,
        unit: &dyn Fn() -> Result<(u32, [u8; 16]), KernelObservationError>,
        context: &ObservationContext<'_>,
    ) -> Result<ObservedUnit, ObservedReadbackUnavailable>;
}

/// No kernel observation could be made, so nothing may be released.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the observed readback set is unavailable")]
pub struct ObservedReadbackUnavailable(#[from] pub(crate) KernelObservationError);

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
    /// The first kernel observation after `ReadyV1` could not be made, or
    /// it is no valid KOE1: KOE1 status 2, with no barrier-failure code.
    #[error("the kernel could not be observed after ReadyV1")]
    FirstObservation(#[source] ObservedReadbackUnavailable),
    /// The recheck could not observe the kernel again (R9 barrier failure
    /// 6).
    #[error("the kernel could not be observed again")]
    RecheckObservation(#[source] ObservedReadbackUnavailable),
    /// The recheck observed other kernel state than was frozen after
    /// `ReadyV1`.
    #[error("the kernel observation changed after ReadyV1")]
    ObservationChanged,
    /// The manager's identity of the unit could not be read again.
    #[error("the unit identity could not be read again")]
    Identity(#[source] Box<dyn Error + Send + Sync>),
    /// The attempt deadline passed while the unit identity was read again.
    #[error("the attempt deadline passed during the identity recheck")]
    Expired,
    /// `/proc/<MainPID>/exe` could not be observed again, for example
    /// because the launcher died.
    #[error("the launcher executable could not be observed again")]
    ExecutableUnreadable,
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
    observed: O,
    cancelled: CancelSignal,
}

impl<R, O> AuthorityCheck<R, O>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
{
    /// Bind the root recheck to the independently admitted policy,
    /// the observed readback source and the attempt's own cancellation
    /// signal, which the lifecycle's cancel and fence set. The authority
    /// heads bound into the release are the admitted attempt's, taken by the
    /// barrier.
    #[must_use]
    pub const fn new(root: R, observed: O, cancelled: CancelSignal) -> Self {
        Self {
            root,
            observed,
            cancelled,
        }
    }

    /// Why a release was refused: cancellation, once requested, outranks
    /// every other refusal (R9: a cancelled attempt reports `Cancelled`).
    fn cancelled_or(&self, refusal: RecheckRefusal) -> RecheckRefusal {
        if self.cancelled.is_requested() {
            RecheckRefusal::Cancelled
        } else {
            refusal
        }
    }

    /// The release binding; `observed` yields the observed readback digest
    /// for the rechecked root.
    fn binding(
        &self,
        admitted: &AdmittedAttempt,
        deadline_monotonic_ns: u64,
        observed: impl FnOnce(&CheckedRoot) -> Result<[u8; 32], RecheckRefusal>,
    ) -> Result<ReleaseBinding, RecheckRefusal> {
        let checked = (self.root)().map_err(RecheckRefusal::Root)?;
        if !checked.matches_attempt(admitted) {
            return Err(RecheckRefusal::Root(ImageActivationError::EvidenceMismatch));
        }
        if self.cancelled.is_requested() {
            return Err(RecheckRefusal::Cancelled);
        }
        let observed_readback_digest = observed(&checked)?;
        let authority = admitted.authority();
        Ok(ReleaseBinding {
            trs1_digest: authority.trs1_digest,
            rvs1_digest: authority.rvs1_digest,
            apt1_digest: authority.apt1_digest,
            trust_epoch: authority.trust_epoch,
            revocation_epoch: authority.revocation_epoch,
            policy_epoch: authority.policy_epoch,
            expected_readback_digest: admitted.expected_readback_digest(),
            observed_readback_digest,
            deadline_monotonic_ns,
        })
    }
}

/// The observation error of an identity read the recheck refused: a read
/// cut off at the attempt deadline is an expiry, and any other a failed
/// manager read.
const fn identity_error(refusal: &RecheckRefusal) -> KernelObservationError {
    if matches!(refusal, RecheckRefusal::Expired) {
        KernelObservationError::IdentityExpired
    } else {
        KernelObservationError::Identity
    }
}

/// Why the recheck's observation failed (ADR-069 R9 §4.6.1): its manager
/// read failed (8), the deadline passed during that read (10), or the
/// observation itself could not be made (6).
fn recheck_observation(unavailable: ObservedReadbackUnavailable) -> RecheckRefusal {
    match unavailable.0 {
        KernelObservationError::Identity => RecheckRefusal::Identity(Box::new(unavailable)),
        KernelObservationError::IdentityExpired => RecheckRefusal::Expired,
        // The unit's network namespace now holds more than `lo` (R14 N12), or
        // a Local network reads back as other state (R14 §3.2): barrier
        // failure 7, as are a namespace that is gone and a unit whose
        // identity moved under the observation (R14 §3.2, error classes). A
        // transport failure is 6.
        KernelObservationError::UnitNetwork(UnitNetworkError::Changed)
        | KernelObservationError::Network(ReadbackError::Changed)
        | KernelObservationError::IdentityChanged
        | KernelObservationError::Namespace(Errno::NOENT) => RecheckRefusal::ObservationChanged,
        _ => RecheckRefusal::RecheckObservation(unavailable),
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
    /// What the kernel observation reads beyond the rechecked root.
    observing: Observing<'a>,
    /// The accepted `ReadyV1`'s digest.
    ready: Cell<Option<[u8; 32]>>,
    /// The attempt's RQE1 self-digest, which its KOE1 binds.
    requested_configuration_evidence: [u8; 32],
    /// The kernel observation frozen once `ReadyV1` was accepted, and its
    /// KOE1.
    frozen: RefCell<Option<Frozen>>,
}

/// The frozen kernel observation and the KOE1 built from it, once.
type Frozen = (ObservedUnit, KernelObservationEvidence);

/// What one kernel observation of the unit needs besides its root.
#[derive(Clone, Copy)]
struct Observing<'a> {
    cgroup: CgroupView<'a>,
    adapter: FdIdentity,
    observed_fdl1_digest: [u8; 32],
    work: bool,
    /// The Local network the observation reads back, if the attempt is
    /// Local.
    network: Option<&'a (dyn NetworkReadback + Sync)>,
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
        let launcher = observe_executable(main_pid).map_err(|_| self.unreadable(main_pid))?;
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

    /// Why `/proc/<main_pid>/exe` could not be observed again: the unit
    /// changed if its `MainPID` did, and otherwise its launcher is gone.
    const fn unreadable(&self, main_pid: u32) -> RecheckRefusal {
        if main_pid == self.snapshot.main_pid {
            RecheckRefusal::ExecutableUnreadable
        } else {
            RecheckRefusal::UnitChanged
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

    fn rechecked(&self, ready1_digest: [u8; 32]) -> Result<ReleaseBinding, RecheckRefusal> {
        self.launcher_then_frozen(ready1_digest)?;
        let binding = self
            .check
            .binding(self.admitted, self.deadline_monotonic_ns, |root| {
                self.observed_again(root)
            })?;
        // The identity is read last, so nothing slower than the read itself
        // separates it from the signing.
        self.unit_unchanged()?;
        remaining_until(self.deadline).map_err(|_| RecheckRefusal::Expired)?;
        Ok(binding)
    }
}

impl<R, O, I> Bounded<'_, R, O, I>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
    I: UnitIdentitySource,
{
    /// Verify the held launcher, then observe the unit's kernel state and
    /// freeze it: the KOE1 observation, made once `ReadyV1` was accepted.
    fn launcher_then_frozen(&self, ready1_digest: [u8; 32]) -> Result<(), RecheckRefusal> {
        // The ReadyV1 was accepted whatever follows: KOE1 status 2 needs it.
        self.ready.set(Some(ready1_digest));
        verify_launcher(&self.launcher.file, &self.launcher.facts)
            .map_err(|_| RecheckRefusal::UnitChanged)?;
        let root = (self.check.root)().map_err(RecheckRefusal::Root)?;
        let observed = self
            .observe(&root)
            .and_then(|observed| {
                observation_evidence(
                    self.admitted.attempt_id(),
                    self.admitted.grant_digest(),
                    ready1_digest,
                    self.requested_configuration_evidence,
                    observed.observation(),
                )
                .map(|evidence| (observed, evidence))
                .map_err(|error| {
                    ObservedReadbackUnavailable(KernelObservationError::Evidence(error))
                })
            })
            .map_err(RecheckRefusal::FirstObservation)?;
        *self.frozen.borrow_mut() = Some(observed);
        Ok(())
    }

    /// Observe again, by the same procedure, and require the frozen
    /// observation: then its KOE1 digest.
    fn observed_again(&self, root: &CheckedRoot) -> Result<[u8; 32], RecheckRefusal> {
        let again = self.observe(root).map_err(recheck_observation)?;
        // Bound to a local so the `RefCell` borrow ends before `again` drops
        // (the tail-expression drop order that Rust 2024 changes).
        let digest = self
            .frozen
            .borrow()
            .as_ref()
            .filter(|(frozen, _)| frozen.observation() == again.observation())
            .map(|(_, evidence)| evidence.digest())
            .ok_or(RecheckRefusal::ObservationChanged);
        digest
    }

    /// One kernel observation of the unit under `root`. Runs under
    /// `block_in_place` on a multi-thread runtime.
    fn observe(&self, root: &CheckedRoot) -> Result<ObservedUnit, ObservedReadbackUnavailable> {
        let handle = tokio::runtime::Handle::current();
        let unit = || {
            self.read_again(&handle, self.identity.main_pid(self.unit_name))
                .and_then(|main_pid| {
                    self.read_again(&handle, self.identity.invocation_id(self.unit_name))
                        .map(|invocation| (main_pid, invocation))
                })
                .map_err(|refusal| identity_error(&refusal))
        };
        let context = ObservationContext::new(
            self.observing.cgroup,
            root.root_identity(),
            self.observing.adapter,
            self.observing.observed_fdl1_digest,
            self.observing.work,
        );
        let context = self.observing.network.map_or(context, |network| {
            context.with_network(network, self.deadline)
        });
        self.check.observed.observe(&unit, &context)
    }
}

impl<R, O, I> ReleaseRecheck for Bounded<'_, R, O, I>
where
    R: Fn() -> Result<CheckedRoot, ImageActivationError>,
    O: ObservedReadback,
    I: UnitIdentitySource,
{
    fn recheck(&self, ready1_digest: [u8; 32]) -> Result<ReleaseBinding, ReleaseBarrierError> {
        self.rechecked(ready1_digest).map_err(|refusal| {
            *self.refusal.borrow_mut() = Some(self.check.cancelled_or(refusal));
            ReleaseBarrierError::Recheck
        })
    }
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
    /// The single-use LPV1 nonce could not be drawn.
    #[error("the launch nonce could not be drawn")]
    Nonce(#[source] io::Error),
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
    /// The adapter could not be observed beneath `/proc/<MainPID>/root`.
    #[error("the adapter could not be observed beneath the unit root")]
    AdapterIdentity(#[source] KernelObservationError),
    /// The attempt deadline passed before any `ReadyV1` was received.
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
    /// `ReleaseV1` was sent, and the attempt deadline passed before the
    /// barrier returned.
    #[error("the attempt deadline passed after the release")]
    ExpiredAfterRelease,
}

impl BarrierError {
    /// The TME1 `barrier-failure` this failure records (ADR-069 R9 §4.6.1;
    /// R9 §11 O5 classes channel faults, among them "`ReadyV1` unavailable",
    /// as code 9 and content faults, among them "recheck expiry", as 10).
    ///
    /// Before any `ReadyV1` was received, the barrier could not read the
    /// unit, hold its launcher, observe its adapter, arm the receive or meet
    /// the deadline: no
    /// `ReadyV1` became available, which is `0 ReadyUnavailable` (R9 §11
    /// O15). After `ReleaseV1` was sent the attempt has progress 2, where
    /// R9 §4.6.3 requires a null `barrier-failure`. `None` is also recorded
    /// for a cancellation (TME1 `cancel-source` records it), a first
    /// observation that failed (KOE1 status 2 records it), a signature that
    /// did not verify under the admitted key (a provider fault), and the
    /// setup failures that precede the launch (O15); the classifier's
    /// fallback or another candidate decides the terminal code.
    #[must_use]
    pub const fn barrier_failure(&self) -> Option<BarrierFailure> {
        match self {
            // Owner decision 2026-11-15 (#443 journal 22319): before
            // ReadyV1, identity failures, the adapter's among them, map to 0.
            Self::Identity(_)
            | Self::LauncherIdentity
            | Self::AdapterIdentity(_)
            | Self::Timeout(_)
            | Self::Expired => Some(BarrierFailure::ReadyUnavailable),
            Self::Release(release) => release_failure(release),
            Self::Refused(refusal) => refusal.barrier_failure(),
            Self::AttemptMismatch
            | Self::Parameters(_)
            | Self::Channel(_)
            | Self::Nonce(_)
            | Self::UnitEndTaken
            | Self::RuntimeFlavor
            | Self::AlreadyAttempted
            | Self::ExpiredAfterRelease => None,
        }
    }
}

/// The `barrier-failure` of a `ReadyV1` receive or `ReleaseV1` send.
const fn release_failure(release: &ReleaseBarrierError) -> Option<BarrierFailure> {
    match release {
        ReleaseBarrierError::ReadyUnavailable => Some(BarrierFailure::ReadyUnavailable),
        ReleaseBarrierError::ReadyFraming => Some(BarrierFailure::ReadyFraming),
        ReleaseBarrierError::PidMismatch => Some(BarrierFailure::ReadyPidMismatch),
        ReleaseBarrierError::ReadyMalformed => Some(BarrierFailure::ReadyMalformed),
        ReleaseBarrierError::ReadyMismatch => Some(BarrierFailure::ReadyMismatch),
        ReleaseBarrierError::ReleaseSend => Some(BarrierFailure::ReleaseSend),
        // The recheck's cause is a [`RecheckRefusal`]; a signature that did
        // not verify is a provider fault.
        ReleaseBarrierError::Recheck | ReleaseBarrierError::Sign(_) => None,
    }
}

impl RecheckRefusal {
    /// The TME1 `barrier-failure` this refusal records (ADR-069 R9 §4.6.1).
    #[must_use]
    pub const fn barrier_failure(&self) -> Option<BarrierFailure> {
        match self {
            Self::Root(_) => Some(BarrierFailure::RecheckAuthority),
            Self::RecheckObservation(_) => Some(BarrierFailure::RecheckObservationUnavailable),
            Self::ObservationChanged => Some(BarrierFailure::RecheckObservationChanged),
            Self::Identity(_) => Some(BarrierFailure::RecheckIdentityUnreadable),
            Self::ExecutableUnreadable => Some(BarrierFailure::RecheckExecutableUnreadable),
            Self::Expired => Some(BarrierFailure::RecheckExpired),
            Self::UnitChanged => Some(BarrierFailure::RecheckUnitChanged),
            Self::Cancelled | Self::FirstObservation(_) => None,
        }
    }
}

/// The production [`LaunchBarrier`].
pub struct ProviderReleaseBarrier<S, I, R, O> {
    admitted: AdmittedAttempt,
    /// The provider's end of the channel (`std` type; the unit's end below is
    /// the `zvariant` type that D-Bus passes).
    provider_end: std::os::fd::OwnedFd,
    unit_end: Option<OwnedFd>,
    parameters: LaunchParameters,
    adapter_digest: [u8; 32],
    signer: S,
    identity: I,
    check: AuthorityCheck<R, O>,
    sent: Option<ExecutionRelease>,
    ready: Option<[u8; 32]>,
    frozen: Option<Frozen>,
    failure: Option<BarrierFailure>,
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
        signer: S,
        identity: I,
        check: AuthorityCheck<R, O>,
    ) -> Result<Self, BarrierError> {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from)
        .map_err(BarrierError::Channel)
        .and_then(|(provider_end, unit_end)| {
            layout_digest(attempt.mode())
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
                .map_err(BarrierError::Parameters)
                .map(|parameters| Self {
                    admitted: attempt.clone(),
                    provider_end,
                    unit_end: Some(OwnedFd::from(unit_end)),
                    parameters,
                    adapter_digest: attempt.executable_digest(),
                    signer,
                    identity,
                    check,
                    sent: None,
                    ready: None,
                    frozen: None,
                    failure: None,
                    attempted: false,
                })
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

/// Identify the very descriptor `file` opened from the running process.
/// Holding it through the handshake prevents a path/stat/hash substitution.
fn hold_launcher(file: File, facts: &crate::LauncherFacts) -> Result<HeldLauncher, BarrierError> {
    verify_launcher_identity(&file, facts).and_then(|()| {
        statx(
            &file,
            "",
            AtFlags::EMPTY_PATH,
            StatxFlags::INO.union(StatxFlags::MNT_ID),
        )
        .ok()
        .filter(|stat| StatxFlags::from_bits_retain(stat.stx_mask).contains(StatxFlags::MNT_ID))
        .map(|stat| HeldLauncher {
            file,
            identity: FdIdentity {
                mount_id: stat.stx_mnt_id,
                inode: stat.stx_ino,
            },
            facts: facts.clone(),
        })
        .ok_or(BarrierError::LauncherIdentity)
    })
}

/// Anchor `main_pid` once, hold its launcher through that anchor, then
/// observe its adapter through the same anchor as the launcher inside the
/// unit sees it: through the unit's own root, so in the unit's mount
/// namespace.
fn hold_launcher_and_adapter(
    main_pid: u32,
    admitted: &AdmittedAttempt,
) -> Result<(HeldLauncher, FdIdentity), BarrierError> {
    crate::MainProcess::open(main_pid)
        .and_then(|process| process.executable().map(|file| (process, file)))
        .map_err(|_| BarrierError::LauncherIdentity)
        .and_then(|(process, file)| {
            hold_launcher(file, admitted.launcher()).and_then(|held| {
                process
                    .adapter(admitted.executable_path())
                    .map(|adapter| (held, adapter))
                    .map_err(BarrierError::AdapterIdentity)
            })
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
    file.metadata()
        .ok()
        .filter(|metadata| {
            (metadata.dev(), metadata.ino()) == facts.identity && metadata.len() == facts.length
        })
        .map(|_| ())
        .ok_or(BarrierError::LauncherIdentity)
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

/// The release was sent: the attempt deadline must not have passed since.
fn released_by(deadline: Instant) -> Result<(), BarrierError> {
    remaining_until(deadline)
        .map(|_| ())
        .map_err(|_| BarrierError::ExpiredAfterRelease)
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

impl<S, I, R, O> ProviderReleaseBarrier<S, I, R, O>
where
    S: RuntimeAttestationSigner + Send + Sync,
    I: UnitIdentitySource + Send + Sync,
    R: Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync,
    O: ObservedReadback + Send + Sync,
{
    async fn release_inner(
        &mut self,
        attempt: &ActiveAttempt,
        cgroup: CgroupView<'_>,
        network: Option<&(dyn NetworkReadback + Sync)>,
    ) -> Result<(), BarrierError> {
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
        let (held_launcher, adapter) =
            tokio::task::block_in_place(|| hold_launcher_and_adapter(main_pid, &self.admitted))?;
        let launcher = held_launcher.identity;
        let expected = self.expected(invocation, launcher, adapter);
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
            observing: Observing {
                cgroup,
                adapter,
                observed_fdl1_digest: self.parameters.expected_fdl1_digest,
                work: self
                    .admitted
                    .service_limits()
                    .is_ok_and(|limits| limits.work_bytes() != 0),
                network,
            },
            ready: Cell::new(None),
            requested_configuration_evidence: attempt.requested_configuration_evidence(),
            frozen: RefCell::new(None),
        };
        let provider_end = &self.provider_end;
        // Every signature is verified under the independently admitted key
        // before the release packet can be serialized or sent.
        let admitted =
            AdmittedRuntimeKey::new(self.admitted.runtime_key_id(), self.admitted.runtime_key());
        let released = tokio::task::block_in_place(|| {
            bound_channel(provider_end, attempt.deadline())?;
            release_after_ready(
                provider_end,
                main_pid,
                &expected,
                &bounded,
                &self.signer,
                admitted,
            )
            .map_err(BarrierError::Release)
        });
        self.ready = bounded.ready.get();
        self.frozen = bounded.frozen.take();
        let release = released
            .map_err(|error| bounded.refusal.take().map_or(error, BarrierError::Refused))?;
        self.sent = Some(release);
        released_by(attempt.deadline())
    }

    const fn expected(
        &self,
        invocation: [u8; 16],
        launcher: FdIdentity,
        adapter: FdIdentity,
    ) -> ExpectedLauncherReady {
        ExpectedLauncherReady {
            attempt_id: self.parameters.attempt_id,
            nonce: self.parameters.nonce,
            launch_instance_id: invocation,
            launcher_digest: self.admitted.launcher().digest,
            launcher_identity: launcher,
            sim1_digest: self.parameters.sim1_digest,
            adapter_digest: self.adapter_digest,
            adapter_identity: adapter,
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
    S: RuntimeAttestationSigner + Send + Sync,
    I: UnitIdentitySource + Send + Sync,
    R: Fn() -> Result<CheckedRoot, ImageActivationError> + Send + Sync,
    O: ObservedReadback + Send + Sync,
{
    type Error = BarrierError;
    type Evidence = ReleaseOutcome;

    fn prepare(
        &mut self,
        attempt: &AdmittedAttempt,
    ) -> Result<(LauncherInvocation, OwnedFd), BarrierError> {
        // Called before the start, so a wrong runtime never starts a unit.
        require_multi_thread()?;
        self.require_attempt(attempt)?;
        LauncherInvocation::from_parameters(&self.parameters)
            .map_err(BarrierError::Parameters)
            .and_then(|invocation| {
                self.unit_end
                    .take()
                    .ok_or(BarrierError::UnitEndTaken)
                    .map(|end| (invocation, end))
            })
    }

    async fn release(
        &mut self,
        attempt: &ActiveAttempt,
        cgroup: CgroupView<'_>,
        network: Option<&(dyn NetworkReadback + Sync)>,
    ) -> Result<(), BarrierError> {
        let released = self.release_inner(attempt, cgroup, network).await;
        // TME1 `barrier-failure` (ADR-069 R9 §4.6.1), kept typed for the
        // terminal records (Redmine #443 journal 22723).
        self.failure = released
            .as_ref()
            .err()
            .and_then(BarrierError::barrier_failure);
        released
    }

    fn evidence(&mut self) -> ReleaseOutcome {
        ReleaseOutcome::new(self.ready.take(), self.frozen.take(), self.sent.take())
            .refused(self.failure.take())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
