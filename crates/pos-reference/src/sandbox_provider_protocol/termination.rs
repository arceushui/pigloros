//! The total ADR-069 R9 terminal classifier (§4.6.4 and §4.6.5), as R10
//! §4.8 extends it with the stdin feed and the pre-start launch failures.
//!
//! [`TerminationFacts`] is the typed view of everything the terminal code
//! depends on: the classification fields of one TME1, the status of the RQE1
//! and the kernel observation of the KOE1 it binds, and the watchdog deadline
//! `D` derived from ELM1. [`TerminationFacts::classify`] is a pure function of
//! those facts. The provider calls it before it freezes TME1, and a verifier
//! that decoded the records calls it again and compares both the
//! `contradiction` and the `terminal-code` it returns (R9 §6 rule 7).
//!
//! Nothing here encodes, digests or signs a record: the TME1, KOE1 and RQE1
//! codecs build these facts from their decoded fields.
//!
//! The classifier fails closed. Contradictory kernel evidence, missing
//! required evidence and every state that selects no code and is not
//! `Completed` select [`TerminalCode::CleanupFailed`] and quarantine the
//! lifecycle. A live V1 provider never selects code 0 `BrokerDied` (R9 D6),
//! so [`TerminalCode`] has no such variant.

use std::num::NonZeroU64;

use super::SandboxTerminalOutcome;

/// The watchdog grace `G` in nanoseconds (R9 §4.6.5; owner, G = 1 s).
///
/// The broker escalates only at `D + G`, and systemd's `timeout` agrees with
/// the authorized watchdog iff the terminal snapshot was taken at or after
/// `D - G`.
pub const WATCHDOG_GRACE_NS: u64 = 1_000_000_000;

/// The `SIGXFSZ` signal number on `x86_64` and `aarch64` (R9 code 7).
const SIGXFSZ: u8 = 25;

/// The watchdog deadline `D`: the unit's `ActiveEnterTimestampMonotonic` in
/// nanoseconds plus ELM1 ID 4.
///
/// A zero (unset) activation or an unrepresentable sum is unreadable, which
/// is `None`: missing evidence (R9 §4.6.5).
#[must_use]
pub const fn attempt_watchdog_deadline(
    activated_monotonic_ns: u64,
    watchdog_ns: u64,
) -> Option<NonZeroU64> {
    match activated_monotonic_ns.checked_add(watchdog_ns) {
        Some(deadline) if activated_monotonic_ns != 0 => NonZeroU64::new(deadline),
        _ => None,
    }
}

/// One terminal observation code of SAU1 events `1..10` (ADR-069 §8).
///
/// Its discriminant is the closed SAU1 event code. Code 0 `BrokerDied` is
/// never produced by a live V1 provider (R9 D6) and has no variant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TerminalCode {
    /// 1: an authenticated cancel request or a revocation stopped the
    /// attempt.
    Cancelled = 1,
    /// 2: cleanup was not proved, or the evidence is contradictory, missing
    /// or unplaceable.
    CleanupFailed = 2,
    /// 3: an out-of-memory kill.
    OomKilled = 3,
    /// 4: the memory or swap maximum was hit.
    MemoryLimit = 4,
    /// 5: the task maximum was hit.
    TaskLimit = 5,
    /// 6: systemd's runtime watchdog fired as authorized.
    Watchdog = 6,
    /// 7: the file-size or output ceiling was reached.
    FileOrOutputLimit = 7,
    /// 8: the payload crashed or exited unsuccessfully.
    ProcessCrash = 8,
    /// 9: a channel to the launcher, the manager or the network failed.
    IpcFailure = 9,
    /// 10: a protocol, launch or transfer failure.
    ProtocolFailure = 10,
}

impl TerminalCode {
    /// Every code, in strict precedence order (lowest wins).
    const ALL: [Self; 10] = [
        Self::Cancelled,
        Self::CleanupFailed,
        Self::OomKilled,
        Self::MemoryLimit,
        Self::TaskLimit,
        Self::Watchdog,
        Self::FileOrOutputLimit,
        Self::ProcessCrash,
        Self::IpcFailure,
        Self::ProtocolFailure,
    ];

    /// The closed SAU1 terminal event code (`1..=10`).
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    const fn position(self) -> usize {
        self as usize - 1
    }
}

/// TME1 `progress`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AttemptProgressCode {
    /// 0: `StartTransientUnit` was never called.
    NotStarted = 0,
    /// 1: the start was requested and no `ReleaseV1` was sent.
    StartedNotReleased = 1,
    /// 2: `ReleaseV1` was sent.
    Released = 2,
}

/// TME1 `launch-failure`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LaunchFailure {
    /// 0: the root image was not activated.
    RootNotActivated = 0,
    /// 1: the recheck immediately before the unit start failed.
    PreStartRecheckFailed = 1,
    /// 2: `RefUnit` failed, so the unit's result could not be pinned.
    UnitRefFailed = 2,
    /// 3: the aggregate staging ledger refused the attempt's output
    /// reservation (R10 §4.7).
    OutputReservationRefused = 3,
    /// 4: a stdio channel could not be created, or descriptor 2 is not the
    /// character device 1:3 (R10 §4.1).
    StdioChannelFailed = 4,
    /// 5: the staging ledger was closed after a cleanup failure, so the
    /// output reservation was refused (R10 §4.7, D5).
    AdmissionClosed = 5,
}

/// TME1 `start-job-result`: systemd's `JobRemoved` result of the start job.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum StartJobResult {
    /// 0: `done`.
    Done = 0,
    /// 1: `canceled`.
    Canceled = 1,
    /// 2: `timeout`.
    Timeout = 2,
    /// 3: `failed`.
    Failed = 3,
    /// 4: `dependency`.
    Dependency = 4,
    /// 5: `skipped`.
    Skipped = 5,
}

/// TME1 `contradiction`: the first failing D5 check (R9 §4.6.4).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Contradiction {
    /// 0: a cgroup, invocation or `/work` identity changed, or the release
    /// recheck saw changed kernel state or a changed unit.
    IdentityChanged = 0,
    /// 1: the terminal snapshot is older than the baseline.
    TimeReversed = 1,
    /// 2: a required counter went down between the snapshots.
    CounterDecreased = 2,
}

/// TME1 `service.result`: the systemd unit `Result`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ServiceResultCode {
    /// 0: `success`.
    Success = 0,
    /// 1: `resources`.
    Resources = 1,
    /// 2: `protocol`.
    Protocol = 2,
    /// 3: `timeout`.
    Timeout = 3,
    /// 4: `exit-code`.
    ExitCode = 4,
    /// 5: `signal`.
    Signal = 5,
    /// 6: `core-dump`.
    CoreDump = 6,
    /// 7: `watchdog`.
    Watchdog = 7,
    /// 8: `start-limit-hit`.
    StartLimitHit = 8,
    /// 9: `oom-kill`.
    OomKill = 9,
    /// 10: `exec-condition`.
    ExecCondition = 10,
}

/// TME1 `service.exec-main-code`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum MainExitCode {
    /// 0: the main process has not exited.
    NotExited = 0,
    /// 1: `CLD_EXITED`; the status is the exit status.
    Exited = 1,
    /// 2: `CLD_KILLED`; the status is the signal number.
    Killed = 2,
    /// 3: `CLD_DUMPED`; the status is the signal number.
    Dumped = 3,
}

/// TME1 `service`: the unit's `Result`, `ExecMainCode` and `ExecMainStatus`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServiceFacts {
    /// The unit `Result`.
    pub result: ServiceResultCode,
    /// The main process's exit code.
    pub exec_main_code: MainExitCode,
    /// The exit status for [`MainExitCode::Exited`], the signal number for
    /// [`MainExitCode::Killed`] and [`MainExitCode::Dumped`].
    pub exec_main_status: u8,
}

impl ServiceFacts {
    /// `[0 success, 1 CLD_EXITED, 0]`, the only service of a `Completed`
    /// attempt.
    pub const CLEAN: Self = Self {
        result: ServiceResultCode::Success,
        exec_main_code: MainExitCode::Exited,
        exec_main_status: 0,
    };

    const fn signaled(self) -> bool {
        matches!(
            self.exec_main_code,
            MainExitCode::Killed | MainExitCode::Dumped
        )
    }

    /// The unit failed before or around exec: a `Result` other than
    /// `success`, `timeout`, `watchdog` and `oom-kill` with no main exit.
    const fn failed_before_exec(self) -> bool {
        !matches!(
            self.result,
            ServiceResultCode::Success
                | ServiceResultCode::Timeout
                | ServiceResultCode::Watchdog
                | ServiceResultCode::OomKill
        ) && matches!(self.exec_main_code, MainExitCode::NotExited)
    }

    const fn crashed(self) -> bool {
        self.signaled()
            || (matches!(self.exec_main_code, MainExitCode::Exited) && self.exec_main_status != 0)
    }

    const fn file_size_exceeded(self) -> bool {
        self.signaled() && self.exec_main_status == SIGXFSZ
    }
}

/// TME1 `ending`: how the released attempt ended.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EndingCode {
    /// 0: the cgroup was observed empty.
    CgroupEmpty = 0,
    /// 1: the broker's watchdog killed the unit.
    WatchdogKilled = 1,
    /// 2: the broker's watchdog could not kill the unit.
    WatchdogKillFailed = 2,
    /// 3: a Local proxy protocol failure killed the unit.
    ProtocolFailureKilled = 3,
    /// 4: a Local proxy protocol failure could not kill the unit.
    ProtocolFailureKillFailed = 4,
    /// 5: the attempt was cancelled.
    Cancelled = 5,
    /// 6: cancelled, and the broker's watchdog killed the unit.
    CancelledWatchdogKilled = 6,
    /// 7: cancelled, and the broker's watchdog could not kill the unit.
    CancelledWatchdogKillFailed = 7,
}

impl EndingCode {
    const fn broker_killed(self) -> bool {
        matches!(
            self,
            Self::WatchdogKilled
                | Self::WatchdogKillFailed
                | Self::CancelledWatchdogKilled
                | Self::CancelledWatchdogKillFailed
        )
    }

    const fn protocol_failure(self) -> bool {
        matches!(
            self,
            Self::ProtocolFailureKilled | Self::ProtocolFailureKillFailed
        )
    }
}

/// TME1 `barrier-failure`: why the launcher barrier did not release.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BarrierFailure {
    /// 0: no `ReadyV1` arrived.
    ReadyUnavailable = 0,
    /// 1: the `ReadyV1` framing was invalid.
    ReadyFraming = 1,
    /// 2: the `ReadyV1` sender was not the unit's main process.
    ReadyPidMismatch = 2,
    /// 3: the `ReadyV1` record was malformed.
    ReadyMalformed = 3,
    /// 4: the `ReadyV1` record disagreed with the attempt.
    ReadyMismatch = 4,
    /// 5: the root, authority or mount recheck failed.
    RecheckAuthority = 5,
    /// 6: the kernel observation could not be made again.
    RecheckObservationUnavailable = 6,
    /// 7: the kernel observation changed since `ReadyV1`.
    RecheckObservationChanged = 7,
    /// 8: the manager's identity of the unit could not be read again.
    RecheckIdentityUnreadable = 8,
    /// 9: `/proc/<MainPID>/exe` could not be read again.
    RecheckExecutableUnreadable = 9,
    /// 10: the attempt deadline passed during the recheck.
    RecheckExpired = 10,
    /// 11: `MainPID`, `InvocationID` or the launcher identity changed.
    RecheckUnitChanged = 11,
    /// 12: `ReleaseV1` could not be sent.
    ReleaseSend = 12,
}

impl BarrierFailure {
    /// Channel faults: code 9.
    const fn channel_fault(self) -> bool {
        matches!(
            self,
            Self::ReadyUnavailable
                | Self::RecheckObservationUnavailable
                | Self::RecheckIdentityUnreadable
                | Self::RecheckExecutableUnreadable
                | Self::ReleaseSend
        )
    }

    /// Content faults: code 10.
    const fn content_fault(self) -> bool {
        matches!(
            self,
            Self::ReadyFraming
                | Self::ReadyPidMismatch
                | Self::ReadyMalformed
                | Self::ReadyMismatch
                | Self::RecheckAuthority
                | Self::RecheckExpired
        )
    }

    /// Identity changes: a D5 contradiction.
    const fn identity_changed(self) -> bool {
        matches!(
            self,
            Self::RecheckObservationChanged | Self::RecheckUnitChanged
        )
    }
}

/// TME1 `local-network.termination`: why a Local proxy session ended.
///
/// `None` in [`TerminationFacts::local_network_termination`] stands for both
/// a null `local-network` and a clean close at a frame boundary; neither
/// selects a code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum LocalNetworkTerminationCode {
    /// 0: an NXY1 `RemoteUnavailable` reply was written.
    RemoteUnavailable = 0,
    /// 1: an NXY1 `DigestMismatch` reply was written.
    DigestMismatch = 1,
    /// 2: the adapter broke the exchange protocol.
    ProtocolFailure = 2,
    /// 3: a capture could not be retained.
    CaptureFailure = 3,
    /// 4: the host-service channel failed.
    ChannelFailure = 4,
}

impl LocalNetworkTerminationCode {
    const fn channel_fault(self) -> bool {
        matches!(
            self,
            Self::RemoteUnavailable | Self::CaptureFailure | Self::ChannelFailure
        )
    }
}

#[cfg(target_os = "linux")]
impl From<super::LocalNetworkTermination> for LocalNetworkTerminationCode {
    fn from(termination: super::LocalNetworkTermination) -> Self {
        match termination {
            super::LocalNetworkTermination::RemoteUnavailable => Self::RemoteUnavailable,
            super::LocalNetworkTermination::DigestMismatch => Self::DigestMismatch,
            super::LocalNetworkTermination::ProtocolFailure => Self::ProtocolFailure,
            super::LocalNetworkTermination::CaptureFailure => Self::CaptureFailure,
            super::LocalNetworkTermination::ChannelFailure => Self::ChannelFailure,
        }
    }
}

/// TME1 `cancel-source`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CancelSource {
    /// 0: an authenticated SCQ1 was accepted.
    CancelRequest = 0,
    /// 1: the attempt was in the required-cancelled set of a live RVS1
    /// update. It is `Cancelled` like a request (owner, 2026-11-13).
    Revocation = 1,
}

/// TME1 `cleanup.result`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CleanupResult {
    /// 0: the terminal cleanup completed.
    Proved = 0,
    /// 1: a cleanup error or deadline.
    NotProved = 1,
    /// 2: withdrawn before any intent was committed.
    NothingCommitted = 2,
}

/// RQE1 `status`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RequestedConfigurationStatus {
    /// 0: the readback was verified.
    Verified = 0,
    /// 1: `StartTransientUnit` was never called.
    NotRequested = 1,
    /// 2: the verifier rejected the readback.
    Mismatch = 2,
    /// 3: the readback could not be obtained.
    ReadbackUnavailable = 3,
}

/// A cgroup's `[major, minor]` device and inode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CgroupIdentity {
    /// The device's major number.
    pub major: u32,
    /// The device's minor number.
    pub minor: u32,
    /// The cgroup directory's inode.
    pub inode: u64,
}

/// TME1 `unit`: the unit's invocation and its bound cgroup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnitIdentity {
    /// The unit's `InvocationID`.
    pub invocation_id: [u8; 16],
    /// The bound cgroup.
    pub cgroup: CgroupIdentity,
}

/// The six required counters of one cgroup snapshot (R9 §4.6.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CgroupCounters {
    /// `memory.events.local` `oom_kill`.
    pub oom_kill: u64,
    /// `memory.events.local` `max`.
    pub memory_max: u64,
    /// `memory.swap.events` `max`.
    pub swap_max: u64,
    /// `pids.events.local` `max`.
    pub pids_max: u64,
    /// `cpu.stat` `nr_throttled` (telemetry only).
    pub nr_throttled: u64,
    /// `cpu.stat` `throttled_usec` (telemetry only).
    pub throttled_usec: u64,
}

impl CgroupCounters {
    /// Whether any counter is lower in `later` than here.
    const fn any_decreased(&self, later: &Self) -> bool {
        self.oom_kill > later.oom_kill
            || self.memory_max > later.memory_max
            || self.swap_max > later.swap_max
            || self.pids_max > later.pids_max
            || self.nr_throttled > later.nr_throttled
            || self.throttled_usec > later.throttled_usec
    }
}

/// TME1 `baseline` or `terminal`, with its sources already parsed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CgroupSnapshot {
    /// The cgroup the sources were read from.
    pub cgroup: CgroupIdentity,
    /// The `CLOCK_MONOTONIC` capture time in nanoseconds.
    pub observed_at: u64,
    /// The parsed required counters.
    pub counters: CgroupCounters,
}

/// The identity and capacity of the `/work` mount: KOE1 `work`.
///
/// It has no free space: free space is volatile and appears only in TME1
/// `work-after` (R9 §4.4).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WorkMountFacts {
    /// The mount ID.
    pub mount_id: u64,
    /// The capacity in bytes.
    pub capacity_bytes: u64,
}

/// TME1 `work-after`: the `/work` `statfs` taken with the terminal snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WorkStatfsFacts {
    /// The mount's identity and capacity, compared with KOE1 `work`.
    pub mount: WorkMountFacts,
    /// The free bytes: recorded, never compared and never terminal (D6).
    pub available_bytes: u64,
}

/// What the attempt's KOE1 recorded.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KernelObservationFacts {
    /// Status 0: the frozen observation's unit identity and `/work`.
    Observed {
        /// The observed `InvocationID`.
        invocation_id: [u8; 16],
        /// The observed cgroup.
        cgroup: CgroupIdentity,
        /// The observed `/work` mount; `None` when ELM1 limit 9 is zero.
        work: Option<WorkMountFacts>,
    },
    /// Status 1: no valid `ReadyV1` was accepted.
    NotReached,
    /// Status 2: `ReadyV1` was accepted but no observation was made.
    ObservationFailed,
}

/// Everything the terminal code depends on (R9 §4.6.5).
///
/// These are the classification fields of one TME1, the RQE1 status and the
/// KOE1 observation it binds, and the watchdog deadline `D`.
///
/// Every R9 field that is nullable is an `Option`. The facts are total: a
/// verifier rejects inconsistent records separately (R9 §6 rule 2), and the
/// classifier still places every value, failing closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TerminationFacts {
    /// TME1 `progress`.
    pub progress: AttemptProgressCode,
    /// TME1 `launch-failure`.
    pub launch_failure: Option<LaunchFailure>,
    /// TME1 `start-job-result`.
    pub start_job: Option<StartJobResult>,
    /// TME1 `unit`.
    pub unit: Option<UnitIdentity>,
    /// TME1 `baseline`.
    pub baseline: Option<CgroupSnapshot>,
    /// TME1 `terminal`.
    pub terminal: Option<CgroupSnapshot>,
    /// TME1 `service`.
    pub service: Option<ServiceFacts>,
    /// TME1 `ending`.
    pub ending: Option<EndingCode>,
    /// TME1 `barrier-failure`.
    pub barrier_failure: Option<BarrierFailure>,
    /// TME1 `input.complete`.
    pub input_complete: bool,
    /// TME1 `adapter-input.complete`: whether the stdin feed was accepted
    /// completely by its deadline (R10 §4.5); `None` when it is null.
    pub adapter_input_complete: Option<bool>,
    /// TME1 `output-capture`.
    pub output_capture: Option<OutputCaptureFacts>,
    /// TME1 `output-transfer.complete`; `None` when no output transfer
    /// started.
    pub output_transfer_complete: Option<bool>,
    /// TME1 `local-network.termination`.
    pub local_network_termination: Option<LocalNetworkTerminationCode>,
    /// TME1 `work-after`.
    pub work_after: Option<WorkStatfsFacts>,
    /// TME1 `watchdog-deadline` (`D`), in `CLOCK_MONOTONIC` nanoseconds.
    ///
    /// `None` when `ActiveEnterTimestampMonotonic` was unreadable or zero
    /// ([`attempt_watchdog_deadline`]): missing evidence once a unit exists.
    pub watchdog_deadline: Option<NonZeroU64>,
    /// TME1 `cancel-source`.
    pub cancel_source: Option<CancelSource>,
    /// TME1 `cleanup.result`.
    pub cleanup: CleanupResult,
    /// The bound RQE1's `status`.
    pub requested: RequestedConfigurationStatus,
    /// The bound KOE1's status and observation.
    pub observed: KernelObservationFacts,
}

/// TME1 `output-capture`, reduced to what classifies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutputCaptureFacts {
    /// The output ceiling (ELM1 ID 8) was reached.
    pub ceiling_reached: bool,
    /// The captured output ended on a complete frame.
    pub complete_frame: bool,
}

impl TerminationFacts {
    /// Classify the attempt: derive the contradiction, collect every
    /// candidate code and select the terminal code (R9 §4.6.5).
    #[must_use]
    pub fn classify(&self) -> TerminalClassification {
        let contradiction = self.contradiction();
        let candidates = self.candidates(contradiction.is_some());
        let code = if contradiction.is_some() {
            Some(TerminalCode::CleanupFailed)
        } else {
            candidates
                .lowest()
                .or_else(|| (!self.completed()).then_some(TerminalCode::CleanupFailed))
        };
        TerminalClassification {
            contradiction,
            candidates,
            code,
        }
    }

    /// The first failing D5 check, in R9 §4.6.4 order.
    fn contradiction(&self) -> Option<Contradiction> {
        let snapshots = self.baseline.zip(self.terminal);
        if self.identity_changed() {
            Some(Contradiction::IdentityChanged)
        } else if snapshots
            .is_some_and(|(baseline, terminal)| baseline.observed_at > terminal.observed_at)
        {
            Some(Contradiction::TimeReversed)
        } else if snapshots
            .is_some_and(|(baseline, terminal)| baseline.counters.any_decreased(&terminal.counters))
        {
            Some(Contradiction::CounterDecreased)
        } else {
            None
        }
    }

    fn identity_changed(&self) -> bool {
        self.cgroups_disagree()
            || self.observation_disagrees()
            || self
                .barrier_failure
                .is_some_and(BarrierFailure::identity_changed)
    }

    /// The present `unit`, `baseline` and `terminal` cgroups are not all
    /// equal.
    fn cgroups_disagree(&self) -> bool {
        let mut present = [
            self.unit.map(|unit| unit.cgroup),
            self.baseline.map(|snapshot| snapshot.cgroup),
            self.terminal.map(|snapshot| snapshot.cgroup),
        ]
        .into_iter()
        .flatten();
        present
            .next()
            .is_some_and(|first| present.any(|other| other != first))
    }

    /// The KOE1 observation disagrees with the unit or `work-after`.
    ///
    /// The `/work` mount and capacity are compared only when `work-after` is
    /// present. Free space is never compared.
    fn observation_disagrees(&self) -> bool {
        match self.observed {
            KernelObservationFacts::Observed {
                invocation_id,
                cgroup,
                work,
            } => {
                self.unit.is_some_and(|unit| {
                    unit.invocation_id != invocation_id || unit.cgroup != cgroup
                }) || work
                    .zip(self.work_after)
                    .is_some_and(|(observed, after)| observed != after.mount)
            }
            KernelObservationFacts::NotReached | KernelObservationFacts::ObservationFailed => false,
        }
    }

    fn service_result(&self) -> Option<ServiceResultCode> {
        self.service.map(|service| service.result)
    }

    fn timed_out(&self) -> bool {
        matches!(self.service_result(), Some(ServiceResultCode::Timeout))
    }

    /// The terminal snapshot was taken at or after `D - G`.
    fn watchdog_reached(&self) -> bool {
        self.terminal
            .zip(self.watchdog_deadline)
            .is_some_and(|(terminal, deadline)| {
                terminal.observed_at.saturating_add(WATCHDOG_GRACE_NS) >= deadline.get()
            })
    }

    /// The broker killed although systemd did not time out, or systemd timed
    /// out before the authorized deadline.
    fn enforcement_disagrees(&self) -> bool {
        let timed_out = self.timed_out();
        (self.ending.is_some_and(EndingCode::broker_killed) && !timed_out)
            || (timed_out && self.terminal.is_some() && !self.watchdog_reached())
    }

    /// Required evidence is absent (R9 O6).
    ///
    /// That is unit evidence out of step with the unit, a field §4.6.3 or
    /// R10 §4.8 requires at this progress, or one of KOE1 `work` and
    /// `work-after` without the other.
    const fn missing_evidence(&self) -> bool {
        let released = matches!(self.progress, AttemptProgressCode::Released);
        self.unit_evidence_missing()
            || (released
                && (self.unit.is_none()
                    || self.service.is_none()
                    || self.ending.is_none()
                    || self.output_capture.is_none()
                    || self.adapter_input_complete.is_none()))
            || (!matches!(self.progress, AttemptProgressCode::NotStarted)
                && self.start_job.is_none())
            || (self.unit.is_none()
                && matches!(self.observed, KernelObservationFacts::Observed { .. }))
            || self.work_presence_differs()
    }

    /// The snapshots and the deadline follow the unit (R9 §4.6.3).
    ///
    /// A unit needs both snapshots, and a snapshot needs a unit. `D` is read
    /// once the start job is done (R9 §4.6.5), so it is required only then:
    /// a failed start job may leave `ActiveEnterTimestampMonotonic` unset.
    const fn unit_evidence_missing(&self) -> bool {
        let started = matches!(self.start_job, Some(StartJobResult::Done));
        let bound = self.unit.is_some();
        (bound
            && (self.baseline.is_none()
                || self.terminal.is_none()
                || (started && self.watchdog_deadline.is_none())))
            || (!bound && (self.baseline.is_some() || self.terminal.is_some()))
    }

    /// KOE1 recorded `/work` and `work-after` did not, or the reverse: both
    /// follow ELM1 limit 9, so one of them is missing.
    const fn work_presence_differs(&self) -> bool {
        match self.observed {
            KernelObservationFacts::Observed { work, .. } => {
                work.is_some() != self.work_after.is_some()
            }
            KernelObservationFacts::NotReached | KernelObservationFacts::ObservationFailed => false,
        }
    }

    /// The code-2 candidates other than a contradiction.
    fn cleanup_failed(&self) -> bool {
        matches!(self.cleanup, CleanupResult::NotProved)
            || matches!(
                self.launch_failure,
                Some(LaunchFailure::UnitRefFailed | LaunchFailure::AdmissionClosed)
            )
            || matches!(self.service_result(), Some(ServiceResultCode::Watchdog))
            || self.enforcement_disagrees()
            || self.missing_evidence()
    }

    /// A counter went up between two uncontradicted snapshots.
    fn increased(&self, contradicted: bool, read: fn(&CgroupCounters) -> u64) -> bool {
        !contradicted
            && self
                .baseline
                .zip(self.terminal)
                .is_some_and(|(baseline, terminal)| {
                    read(&terminal.counters) > read(&baseline.counters)
                })
    }

    fn oom_killed(&self, contradicted: bool) -> bool {
        matches!(self.service_result(), Some(ServiceResultCode::OomKill))
            || self.increased(contradicted, |counters| counters.oom_kill)
    }

    fn memory_limited(&self, contradicted: bool) -> bool {
        self.increased(contradicted, |counters| counters.memory_max)
            || self.increased(contradicted, |counters| counters.swap_max)
    }

    fn file_or_output_limited(&self) -> bool {
        self.service.is_some_and(ServiceFacts::file_size_exceeded)
            || self
                .output_capture
                .is_some_and(|capture| capture.ceiling_reached)
    }

    fn ipc_failed(&self) -> bool {
        matches!(self.launch_failure, Some(LaunchFailure::StdioChannelFailed))
            || self
                .barrier_failure
                .is_some_and(BarrierFailure::channel_fault)
            || self
                .local_network_termination
                .is_some_and(LocalNetworkTerminationCode::channel_fault)
    }

    fn protocol_failed(&self) -> bool {
        self.barrier_failure
            .is_some_and(BarrierFailure::content_fault)
            || matches!(
                self.launch_failure,
                Some(
                    LaunchFailure::RootNotActivated
                        | LaunchFailure::PreStartRecheckFailed
                        | LaunchFailure::OutputReservationRefused
                )
            )
            || self
                .start_job
                .is_some_and(|job| job != StartJobResult::Done)
            || matches!(
                self.requested,
                RequestedConfigurationStatus::Mismatch
                    | RequestedConfigurationStatus::ReadbackUnavailable
            )
            || self.service.is_some_and(ServiceFacts::failed_before_exec)
            || self.transfer_failed()
    }

    fn transfer_failed(&self) -> bool {
        !self.input_complete
            || self.adapter_input_complete == Some(false)
            || self.output_transfer_complete == Some(false)
            || self.ending.is_some_and(EndingCode::protocol_failure)
            || matches!(
                self.local_network_termination,
                Some(
                    LocalNetworkTerminationCode::DigestMismatch
                        | LocalNetworkTerminationCode::ProtocolFailure
                )
            )
            || (matches!(self.progress, AttemptProgressCode::Released)
                && self
                    .output_capture
                    .is_some_and(|capture| !(capture.complete_frame || capture.ceiling_reached)))
    }

    fn candidates(&self, contradicted: bool) -> TerminalCandidates {
        TerminalCandidates([
            self.cancel_source.is_some(),
            contradicted || self.cleanup_failed(),
            self.oom_killed(contradicted),
            self.memory_limited(contradicted),
            self.increased(contradicted, |counters| counters.pids_max),
            self.timed_out() && self.watchdog_reached(),
            self.file_or_output_limited(),
            self.service.is_some_and(ServiceFacts::crashed),
            self.ipc_failed(),
            self.protocol_failed(),
        ])
    }

    /// The `Completed` conditions an empty candidate set does not imply.
    ///
    /// With no candidate, a released attempt has a `done` start job and an
    /// output capture on a complete frame, since anything else is a
    /// candidate.
    fn completed(&self) -> bool {
        matches!(self.progress, AttemptProgressCode::Released)
            && self.service == Some(ServiceFacts::CLEAN)
            && matches!(self.requested, RequestedConfigurationStatus::Verified)
            && matches!(self.observed, KernelObservationFacts::Observed { .. })
            && matches!(self.cleanup, CleanupResult::Proved)
    }
}

/// The set of candidate codes of one attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TerminalCandidates([bool; 10]);

impl TerminalCandidates {
    /// Whether `code` is a candidate.
    #[must_use]
    pub const fn contains(self, code: TerminalCode) -> bool {
        self.0[code.position()]
    }

    /// The candidate of strictest precedence.
    fn lowest(self) -> Option<TerminalCode> {
        TerminalCode::ALL
            .into_iter()
            .find(|code| self.contains(*code))
    }
}

/// The classification of one attempt (R9 §4.6.4 and §4.6.5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TerminalClassification {
    contradiction: Option<Contradiction>,
    candidates: TerminalCandidates,
    code: Option<TerminalCode>,
}

impl TerminalClassification {
    /// TME1 `contradiction`.
    #[must_use]
    pub const fn contradiction(&self) -> Option<Contradiction> {
        self.contradiction
    }

    /// Every candidate code, including any the selected code outranked.
    #[must_use]
    pub const fn candidates(&self) -> TerminalCandidates {
        self.candidates
    }

    /// TME1 `terminal-code`; `None` is `Completed`.
    #[must_use]
    pub const fn code(&self) -> Option<TerminalCode> {
        self.code
    }

    /// Whether the lifecycle is quarantined: code 2 was selected or is an
    /// outranked candidate (R9 §4.6.1).
    #[must_use]
    pub const fn quarantined(&self) -> bool {
        matches!(self.code, Some(TerminalCode::CleanupFailed))
            || self.candidates.contains(TerminalCode::CleanupFailed)
    }

    /// The SPY1 outcome (R9 §6 rule 8).
    ///
    /// It is `Completed` iff there is no code, `Cancelled` iff code 1 (a
    /// cancel request or a revocation), and otherwise
    /// `UnavailableAfterAdmission`.
    #[must_use]
    pub const fn outcome(&self) -> SandboxTerminalOutcome {
        match self.code {
            None => SandboxTerminalOutcome::Completed,
            Some(TerminalCode::Cancelled) => SandboxTerminalOutcome::Cancelled,
            Some(_) => SandboxTerminalOutcome::UnavailableAfterAdmission,
        }
    }
}
