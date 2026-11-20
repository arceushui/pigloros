//! The ADR-069 R9 §4.6.5 totality obligation for the public terminal
//! classifier, with the R10 §4.8 rows for the stdin feed and launch failures
//! 3 to 5.
//!
//! An independent oracle restates R9's candidate table and R10's added rows, the D5 contradiction
//! order and the literal `Completed` conditions with the closed numeric codes,
//! which a literal table pins to the R9 numbers.
//!
//! R9's "every point" is the full Cartesian product of the coded and null
//! dimensions, about 2 x 10^9 points, so it is covered by decomposition. The
//! code is `select(contradiction, candidates, completed)`; each candidate row
//! reads a few fields, and selection reads only the candidate set, the
//! contradiction and the `Completed` conditions. The tests therefore:
//!
//! * enumerate, in counted groups, the full product of the fields that
//!   interact within one or more rows (including a cross group of service,
//!   ending, cleanup, cancel and contradiction), checking every point against
//!   the oracle and the exact fallback condition;
//! * realize all 1024 candidate sets, with and without a contradiction, and
//!   check the selected code;
//! * draw seeded random concrete facts over every field at once, so any
//!   interaction between groups is checked against the oracle, and require
//!   every class-preserving change of the concrete values to keep the
//!   classification.

use std::num::NonZeroU64;

use pos_reference::sandbox_provider_protocol::{
    attempt_watchdog_deadline, AttemptProgressCode, BarrierFailure, CancelSource, CgroupCounters,
    CgroupIdentity, CgroupSnapshot, CleanupResult, Contradiction, EndingCode,
    KernelObservationFacts, LaunchFailure, LocalNetworkTerminationCode, MainExitCode,
    OutputCaptureFacts, RequestedConfigurationStatus, SandboxTerminalOutcome, ServiceFacts,
    ServiceResultCode, StartJobResult, TerminalClassification, TerminalCode, TerminationFacts,
    UnitIdentity, WorkMountFacts, WorkStatfsFacts, WATCHDOG_GRACE_NS,
};

const GRACE: u64 = 1_000_000_000;
/// `SIGXFSZ` on `x86_64` and `aarch64` (R9 code 7).
const SIGXFSZ: u8 = 25;
/// Every terminal code, in R9 precedence order.
const CODES: [TerminalCode; 10] = [
    TerminalCode::Cancelled,
    TerminalCode::CleanupFailed,
    TerminalCode::OomKilled,
    TerminalCode::MemoryLimit,
    TerminalCode::TaskLimit,
    TerminalCode::Watchdog,
    TerminalCode::FileOrOutputLimit,
    TerminalCode::ProcessCrash,
    TerminalCode::IpcFailure,
    TerminalCode::ProtocolFailure,
];
const BASELINE_AT: u64 = 1_000_000_000_000;
const TERMINAL_AT: u64 = 1_000_250_000_000;
const DEADLINE: u64 = 1_005_000_000_000;
const CGROUP: CgroupIdentity = CgroupIdentity {
    major: 0,
    minor: 26,
    inode: 5678,
};
const OTHER_CGROUP: CgroupIdentity = CgroupIdentity {
    major: 0,
    minor: 26,
    inode: 5679,
};
const INVOCATION: [u8; 16] = [0x77; 16];
const OTHER_INVOCATION: [u8; 16] = [0x78; 16];
const WORK: WorkMountFacts = WorkMountFacts {
    mount_id: 302,
    capacity_bytes: 1_048_576,
};
const COUNTERS: CgroupCounters = CgroupCounters {
    oom_kill: 1,
    memory_max: 2,
    swap_max: 3,
    pids_max: 4,
    nr_throttled: 5,
    throttled_usec: 6,
};

const PROGRESS: [AttemptProgressCode; 3] = [
    AttemptProgressCode::NotStarted,
    AttemptProgressCode::StartedNotReleased,
    AttemptProgressCode::Released,
];
const LAUNCH: [Option<LaunchFailure>; 7] = [
    None,
    Some(LaunchFailure::RootNotActivated),
    Some(LaunchFailure::PreStartRecheckFailed),
    Some(LaunchFailure::UnitRefFailed),
    Some(LaunchFailure::OutputReservationRefused),
    Some(LaunchFailure::StdioChannelFailed),
    Some(LaunchFailure::AdmissionClosed),
];
const START: [Option<StartJobResult>; 7] = [
    None,
    Some(StartJobResult::Done),
    Some(StartJobResult::Canceled),
    Some(StartJobResult::Timeout),
    Some(StartJobResult::Failed),
    Some(StartJobResult::Dependency),
    Some(StartJobResult::Skipped),
];
const RESULTS: [ServiceResultCode; 11] = [
    ServiceResultCode::Success,
    ServiceResultCode::Resources,
    ServiceResultCode::Protocol,
    ServiceResultCode::Timeout,
    ServiceResultCode::ExitCode,
    ServiceResultCode::Signal,
    ServiceResultCode::CoreDump,
    ServiceResultCode::Watchdog,
    ServiceResultCode::StartLimitHit,
    ServiceResultCode::OomKill,
    ServiceResultCode::ExecCondition,
];
const EXITS: [MainExitCode; 4] = [
    MainExitCode::NotExited,
    MainExitCode::Exited,
    MainExitCode::Killed,
    MainExitCode::Dumped,
];
/// `exec-main-status` reduced to its classes {0, 25, other}.
const STATUS_CLASSES: [u8; 3] = [0, SIGXFSZ, 9];
const ENDINGS: [Option<EndingCode>; 9] = [
    None,
    Some(EndingCode::CgroupEmpty),
    Some(EndingCode::WatchdogKilled),
    Some(EndingCode::WatchdogKillFailed),
    Some(EndingCode::ProtocolFailureKilled),
    Some(EndingCode::ProtocolFailureKillFailed),
    Some(EndingCode::Cancelled),
    Some(EndingCode::CancelledWatchdogKilled),
    Some(EndingCode::CancelledWatchdogKillFailed),
];
const BARRIERS: [Option<BarrierFailure>; 14] = [
    None,
    Some(BarrierFailure::ReadyUnavailable),
    Some(BarrierFailure::ReadyFraming),
    Some(BarrierFailure::ReadyPidMismatch),
    Some(BarrierFailure::ReadyMalformed),
    Some(BarrierFailure::ReadyMismatch),
    Some(BarrierFailure::RecheckAuthority),
    Some(BarrierFailure::RecheckObservationUnavailable),
    Some(BarrierFailure::RecheckObservationChanged),
    Some(BarrierFailure::RecheckIdentityUnreadable),
    Some(BarrierFailure::RecheckExecutableUnreadable),
    Some(BarrierFailure::RecheckExpired),
    Some(BarrierFailure::RecheckUnitChanged),
    Some(BarrierFailure::ReleaseSend),
];
const NETWORK: [Option<LocalNetworkTerminationCode>; 6] = [
    None,
    Some(LocalNetworkTerminationCode::RemoteUnavailable),
    Some(LocalNetworkTerminationCode::DigestMismatch),
    Some(LocalNetworkTerminationCode::ProtocolFailure),
    Some(LocalNetworkTerminationCode::CaptureFailure),
    Some(LocalNetworkTerminationCode::ChannelFailure),
];
const CANCEL: [Option<CancelSource>; 3] = [
    None,
    Some(CancelSource::CancelRequest),
    Some(CancelSource::Revocation),
];
const CLEANUP: [CleanupResult; 3] = [
    CleanupResult::Proved,
    CleanupResult::NotProved,
    CleanupResult::NothingCommitted,
];
const REQUESTED: [RequestedConfigurationStatus; 4] = [
    RequestedConfigurationStatus::Verified,
    RequestedConfigurationStatus::NotRequested,
    RequestedConfigurationStatus::Mismatch,
    RequestedConfigurationStatus::ReadbackUnavailable,
];
const OBSERVED: KernelObservationFacts = KernelObservationFacts::Observed {
    invocation_id: INVOCATION,
    cgroup: CGROUP,
    work: Some(WORK),
};
const OBSERVATIONS: [KernelObservationFacts; 3] = [
    OBSERVED,
    KernelObservationFacts::NotReached,
    KernelObservationFacts::ObservationFailed,
];
const CAPTURES: [Option<OutputCaptureFacts>; 5] = [
    None,
    Some(capture(false, false)),
    Some(capture(false, true)),
    Some(capture(true, false)),
    Some(capture(true, true)),
];
const OUTPUT_TRANSFERS: [Option<bool>; 3] = [None, Some(true), Some(false)];
/// `adapter-input` null, complete or incomplete (R10 §4.8 totality).
const FEEDS: [Option<bool>; 3] = [None, Some(true), Some(false)];
const BOOLS: [bool; 2] = [false, true];

const fn capture(ceiling_reached: bool, complete_frame: bool) -> OutputCaptureFacts {
    OutputCaptureFacts {
        ceiling_reached,
        complete_frame,
    }
}

const fn snapshot(observed_at: u64, counters: CgroupCounters) -> CgroupSnapshot {
    CgroupSnapshot {
        cgroup: CGROUP,
        observed_at,
        counters,
    }
}

const fn service(
    result: ServiceResultCode,
    exec_main_code: MainExitCode,
    exec_main_status: u8,
) -> ServiceFacts {
    ServiceFacts {
        result,
        exec_main_code,
        exec_main_status,
    }
}

/// TME1-A: a released attempt that completed cleanly.
const fn completed() -> TerminationFacts {
    TerminationFacts {
        progress: AttemptProgressCode::Released,
        launch_failure: None,
        start_job: Some(StartJobResult::Done),
        unit: Some(UnitIdentity {
            invocation_id: INVOCATION,
            cgroup: CGROUP,
        }),
        baseline: Some(snapshot(BASELINE_AT, COUNTERS)),
        terminal: Some(snapshot(TERMINAL_AT, COUNTERS)),
        service: Some(ServiceFacts::CLEAN),
        ending: Some(EndingCode::CgroupEmpty),
        barrier_failure: None,
        input_complete: true,
        adapter_input_complete: Some(true),
        output_capture: Some(capture(false, true)),
        output_transfer_complete: None,
        local_network_termination: None,
        work_after: Some(WorkStatfsFacts {
            mount: WORK,
            available_bytes: 1_044_480,
        }),
        watchdog_deadline: NonZeroU64::new(DEADLINE),
        cancel_source: None,
        cleanup: CleanupResult::Proved,
        requested: RequestedConfigurationStatus::Verified,
        observed: OBSERVED,
    }
}

/// A progress-0 attempt: nothing was started, observed or measured.
const fn unstarted() -> TerminationFacts {
    TerminationFacts {
        progress: AttemptProgressCode::NotStarted,
        start_job: None,
        unit: None,
        baseline: None,
        terminal: None,
        service: None,
        ending: None,
        output_capture: None,
        adapter_input_complete: None,
        work_after: None,
        requested: RequestedConfigurationStatus::NotRequested,
        observed: KernelObservationFacts::NotReached,
        ..completed()
    }
}

// ---------------------------------------------------------------------------
// The independent oracle, restated from R9 with numeric codes.

#[derive(Debug, Eq, PartialEq)]
struct Expected {
    contradiction: Option<u8>,
    /// Index `n` is candidate code `n`; index 0 (`BrokerDied`) stays false.
    candidates: [bool; 11],
    code: Option<u8>,
    fallback: bool,
}

fn code_of<T: Copy>(value: Option<T>, numeric: fn(T) -> u8) -> Option<u8> {
    value.map(numeric)
}

fn in_set(value: Option<u8>, set: &[u8]) -> bool {
    value.is_some_and(|value| set.contains(&value))
}

fn oracle_contradiction(facts: &TerminationFacts) -> Option<u8> {
    let snapshots = facts.baseline.zip(facts.terminal);
    let cgroups: Vec<CgroupIdentity> = [
        facts.unit.map(|unit| unit.cgroup),
        facts.baseline.map(|snapshot| snapshot.cgroup),
        facts.terminal.map(|snapshot| snapshot.cgroup),
    ]
    .into_iter()
    .flatten()
    .collect();
    let observed_identity = match facts.observed {
        KernelObservationFacts::Observed {
            invocation_id,
            cgroup,
            work,
        } => {
            facts
                .unit
                .is_some_and(|unit| (unit.invocation_id, unit.cgroup) != (invocation_id, cgroup))
                || work
                    .zip(facts.work_after)
                    .is_some_and(|(observed, after)| observed != after.mount)
        }
        _ => false,
    };
    let barrier = code_of(facts.barrier_failure, |failure| failure as u8);
    if cgroups.windows(2).any(|pair| pair[0] != pair[1])
        || observed_identity
        || in_set(barrier, &[7, 11])
    {
        Some(0)
    } else if snapshots
        .is_some_and(|(baseline, terminal)| baseline.observed_at > terminal.observed_at)
    {
        Some(1)
    } else if snapshots.is_some_and(|(baseline, terminal)| {
        counter_values(&baseline.counters)
            .into_iter()
            .zip(counter_values(&terminal.counters))
            .any(|(before, after)| before > after)
    }) {
        Some(2)
    } else {
        None
    }
}

const fn counter_values(counters: &CgroupCounters) -> [u64; 6] {
    [
        counters.oom_kill,
        counters.memory_max,
        counters.swap_max,
        counters.pids_max,
        counters.nr_throttled,
        counters.throttled_usec,
    ]
}

/// Missing evidence (R9 O6), §4.6.3's required fields and R10's
/// `adapter-input` at progress 2.
const fn oracle_missing(facts: &TerminationFacts) -> bool {
    let progress = facts.progress as u8;
    let snapshots = facts.baseline.is_some() && facts.terminal.is_some();
    (facts.unit.is_some() && !snapshots)
        || (progress == 2 && facts.service.is_none())
        || (progress == 2
            && (facts.unit.is_none() || facts.ending.is_none() || facts.output_capture.is_none()))
        || (progress == 2 && facts.adapter_input_complete.is_none())
        || (progress >= 1 && facts.start_job.is_none())
        || (facts.unit.is_none()
            && matches!(facts.observed, KernelObservationFacts::Observed { .. }))
        || match facts.observed {
            KernelObservationFacts::Observed { work, .. } => {
                work.is_some() != facts.work_after.is_some()
            }
            _ => false,
        }
        || oracle_unit_evidence_missing(facts)
}

/// R9 §4.6.3, read row by row: `baseline` is present only if `unit` is
/// (else missing evidence); `terminal` is present iff `baseline` is; and an
/// unreadable `ActiveEnterTimestampMonotonic` is missing evidence (§4.6.5:
/// `D` is read once the start job is done).
const fn oracle_unit_evidence_missing(facts: &TerminationFacts) -> bool {
    let done = matches!(facts.start_job, Some(StartJobResult::Done));
    let has_unit = facts.unit.is_some();
    let has_baseline = facts.baseline.is_some();
    let has_deadline = facts.watchdog_deadline.is_some();
    (has_baseline && !has_unit)
        || (facts.terminal.is_some() != has_baseline)
        || (done && has_unit && !has_deadline)
}

/// `terminal.observed-at >= D - G`, in exact integer arithmetic.
fn oracle_watchdog_reached(facts: &TerminationFacts) -> bool {
    facts
        .terminal
        .zip(facts.watchdog_deadline)
        .is_some_and(|(terminal, deadline)| {
            i128::from(terminal.observed_at) >= i128::from(deadline.get()) - i128::from(GRACE)
        })
}

fn oracle_code_two(facts: &TerminationFacts, contradiction: Option<u8>) -> bool {
    let result = code_of(facts.service, |service| service.result as u8);
    let ending = code_of(facts.ending, |ending| ending as u8);
    let enforcement = (in_set(ending, &[1, 2, 6, 7]) && result != Some(3))
        || (result == Some(3) && facts.terminal.is_some() && !oracle_watchdog_reached(facts));
    contradiction.is_some()
        || facts.cleanup as u8 == 1
        || in_set(
            code_of(facts.launch_failure, |failure| failure as u8),
            &[2, 5],
        )
        || result == Some(7)
        || enforcement
        || oracle_missing(facts)
}

fn oracle_increase(facts: &TerminationFacts, contradiction: Option<u8>, index: usize) -> bool {
    contradiction.is_none()
        && facts
            .baseline
            .zip(facts.terminal)
            .is_some_and(|(baseline, terminal)| {
                counter_values(&terminal.counters)[index]
                    > counter_values(&baseline.counters)[index]
            })
}

fn oracle_exit(facts: &TerminationFacts) -> (Option<u8>, Option<u8>, u8) {
    facts.service.map_or((None, None, 0), |service| {
        (
            Some(service.result as u8),
            Some(service.exec_main_code as u8),
            service.exec_main_status,
        )
    })
}

fn oracle_code_ten(facts: &TerminationFacts) -> bool {
    let (result, exec, _) = oracle_exit(facts);
    let network = code_of(facts.local_network_termination, |termination| {
        termination as u8
    });
    in_set(
        code_of(facts.barrier_failure, |failure| failure as u8),
        &[1, 2, 3, 4, 5, 10],
    ) || in_set(
        code_of(facts.launch_failure, |failure| failure as u8),
        &[0, 1, 3],
    ) || in_set(code_of(facts.start_job, |job| job as u8), &[1, 2, 3, 4, 5])
        || [2, 3].contains(&(facts.requested as u8))
        || (result.is_some_and(|result| ![0, 3, 7, 9].contains(&result)) && exec == Some(0))
        || !facts.input_complete
        || facts.adapter_input_complete == Some(false)
        || facts.output_transfer_complete == Some(false)
        || in_set(code_of(facts.ending, |ending| ending as u8), &[3, 4])
        || in_set(network, &[1, 2])
        || (facts.progress as u8 == 2
            && facts
                .output_capture
                .is_some_and(|capture| !(capture.complete_frame || capture.ceiling_reached)))
}

fn oracle_candidates(facts: &TerminationFacts, contradiction: Option<u8>) -> [bool; 11] {
    let (result, exec, status) = oracle_exit(facts);
    let signaled = in_set(exec, &[2, 3]);
    let network = code_of(facts.local_network_termination, |termination| {
        termination as u8
    });
    let increase = |index| oracle_increase(facts, contradiction, index);
    [
        false,
        facts.cancel_source.is_some(),
        oracle_code_two(facts, contradiction),
        increase(0) || result == Some(9),
        increase(1) || increase(2),
        increase(3),
        result == Some(3) && oracle_watchdog_reached(facts),
        (signaled && status == 25) || facts.output_capture.is_some_and(|c| c.ceiling_reached),
        signaled || (exec == Some(1) && status != 0),
        in_set(
            code_of(facts.barrier_failure, |failure| failure as u8),
            &[0, 6, 8, 9, 12],
        ) || in_set(network, &[0, 3, 4])
            || code_of(facts.launch_failure, |failure| failure as u8) == Some(4),
        oracle_code_ten(facts),
    ]
}

/// R9 §4.6.5's literal `Completed` conditions, all six of them.
fn oracle_completed(facts: &TerminationFacts) -> bool {
    facts.progress as u8 == 2
        && code_of(facts.start_job, |job| job as u8) == Some(0)
        && facts.service.map(|service| {
            (
                service.result as u8,
                service.exec_main_code as u8,
                service.exec_main_status,
            )
        }) == Some((0, 1, 0))
        && facts
            .output_capture
            .is_some_and(|capture| capture.complete_frame)
        && facts.requested as u8 == 0
        && matches!(facts.observed, KernelObservationFacts::Observed { .. })
        && facts.cleanup as u8 == 0
}

fn oracle(facts: &TerminationFacts) -> Expected {
    let contradiction = oracle_contradiction(facts);
    let candidates = oracle_candidates(facts, contradiction);
    let lowest = (1..=10u8).find(|code| candidates[usize::from(*code)]);
    let (code, fallback) = match (contradiction, lowest) {
        (Some(_), _) => (Some(2), false),
        (None, Some(code)) => (Some(code), false),
        (None, None) if oracle_completed(facts) => (None, false),
        (None, None) => (Some(2), true),
    };
    Expected {
        contradiction,
        candidates,
        code,
        fallback,
    }
}

// ---------------------------------------------------------------------------
// Comparison and enumeration.

fn observed(classification: &TerminalClassification) -> Expected {
    let mut candidates = [false; 11];
    for code in CODES {
        candidates[usize::from(code.code())] = classification.candidates().contains(code);
    }
    let code = classification.code().map(TerminalCode::code);
    Expected {
        contradiction: classification.contradiction().map(|found| found as u8),
        candidates,
        code,
        fallback: code == Some(2) && !candidates[2],
    }
}

const fn expected_outcome(code: Option<u8>) -> SandboxTerminalOutcome {
    match code {
        None => SandboxTerminalOutcome::Completed,
        Some(1) => SandboxTerminalOutcome::Cancelled,
        Some(_) => SandboxTerminalOutcome::UnavailableAfterAdmission,
    }
}

/// Classify one point and require the oracle's exact result. Returns whether
/// the point reached the fail-closed fallback.
fn check(facts: &TerminationFacts) -> bool {
    let classification = facts.classify();
    let expected = oracle(facts);
    let found = observed(&classification);
    assert_eq!(found, expected, "{facts:?}");
    // The fallback is reached exactly when nothing is a candidate, nothing
    // contradicts and the literal `Completed` conditions fail.
    assert_eq!(
        found.fallback,
        found.contradiction.is_none()
            && !found.candidates.contains(&true)
            && !oracle_completed(facts),
        "{facts:?}"
    );
    assert!(
        expected.code.is_none_or(|code| (1..=10).contains(&code)),
        "{facts:?}"
    );
    assert_eq!(
        classification.quarantined(),
        expected.code == Some(2) || expected.candidates[2],
        "{facts:?}"
    );
    assert_eq!(
        classification.outcome(),
        expected_outcome(expected.code),
        "{facts:?}"
    );
    expected.fallback
}

type Setter = Box<dyn Fn(&mut TerminationFacts)>;

fn dimension<T: Copy + 'static>(values: &[T], set: fn(&mut TerminationFacts, T)) -> Vec<Setter> {
    values
        .iter()
        .map(|&value| Box::new(move |facts: &mut TerminationFacts| set(facts, value)) as Setter)
        .collect()
}

fn enumerate(
    facts: &TerminationFacts,
    dimensions: &[Vec<Setter>],
    visit: &mut dyn FnMut(&TerminationFacts),
) {
    match dimensions.split_first() {
        None => visit(facts),
        Some((first, rest)) => {
            for setter in first {
                let mut next = *facts;
                setter(&mut next);
                enumerate(&next, rest, visit);
            }
        }
    }
}

/// Check every point of the Cartesian product of `dimensions` over `base`.
/// Returns the number of points and how many reached the fallback.
fn exhaust(base: &TerminationFacts, dimensions: &[Vec<Setter>]) -> (usize, usize) {
    let mut points = 0;
    let mut fallbacks = 0;
    enumerate(base, dimensions, &mut |facts| {
        points += 1;
        fallbacks += usize::from(check(facts));
    });
    let product: usize = dimensions.iter().map(Vec::len).product();
    assert_eq!(points, product);
    (points, fallbacks)
}

fn services() -> Vec<Option<ServiceFacts>> {
    let mut all = vec![None];
    for result in RESULTS {
        for exec in EXITS {
            for status in STATUS_CLASSES {
                all.push(Some(service(result, exec, status)));
            }
        }
    }
    all
}

fn set_snapshot(slot: &mut Option<CgroupSnapshot>, present: bool, at: u64) {
    *slot = present.then(|| snapshot(at, COUNTERS));
}

/// Set one terminal counter one below, equal to or one above its baseline.
fn set_terminal_counter(facts: &mut TerminationFacts, index: usize, relation: i8) {
    if let Some(terminal) = facts.terminal.as_mut() {
        let mut values = counter_values(&terminal.counters);
        values[index] = counter_values(&COUNTERS)[index].saturating_add_signed(i64::from(relation));
        terminal.counters = counters_from(values);
    }
}

const fn set_cgroup(slot: &mut Option<CgroupSnapshot>, differs: bool) {
    if let Some(snapshot) = slot.as_mut() {
        snapshot.cgroup = if differs { OTHER_CGROUP } else { CGROUP };
    }
}

const fn counters_from(values: [u64; 6]) -> CgroupCounters {
    CgroupCounters {
        oom_kill: values[0],
        memory_max: values[1],
        swap_max: values[2],
        pids_max: values[3],
        nr_throttled: values[4],
        throttled_usec: values[5],
    }
}

fn with_observation(
    facts: &mut TerminationFacts,
    change: impl FnOnce(&mut [u8; 16], &mut CgroupIdentity, &mut Option<WorkMountFacts>),
) {
    if let KernelObservationFacts::Observed {
        invocation_id,
        cgroup,
        work,
    } = &mut facts.observed
    {
        change(invocation_id, cgroup, work);
    }
}

// ---------------------------------------------------------------------------
// Exhaustive tests.

#[test]
fn every_lifecycle_code_and_status_is_placed_exactly_once() {
    let (points, fallbacks) = exhaust(
        &completed(),
        &[
            dimension(&PROGRESS, |facts, value| facts.progress = value),
            dimension(&LAUNCH, |facts, value| facts.launch_failure = value),
            dimension(&START, |facts, value| facts.start_job = value),
            dimension(&BARRIERS, |facts, value| facts.barrier_failure = value),
            dimension(&CANCEL, |facts, value| facts.cancel_source = value),
            dimension(&CLEANUP, |facts, value| facts.cleanup = value),
            dimension(&REQUESTED, |facts, value| facts.requested = value),
            dimension(&OBSERVATIONS, |facts, value| facts.observed = value),
        ],
    );
    assert_eq!(points, 3 * 7 * 7 * 14 * 3 * 3 * 4 * 3);
    assert!(fallbacks > 0);
}

#[test]
fn every_unit_phase_value_and_watchdog_class_is_placed_exactly_once() {
    let services = services();
    let (points, fallbacks) = exhaust(
        &completed(),
        &[
            dimension(&PROGRESS, |facts, value| facts.progress = value),
            dimension(&BOOLS, |facts, present| {
                facts.unit = present.then_some(UnitIdentity {
                    invocation_id: INVOCATION,
                    cgroup: CGROUP,
                });
            }),
            dimension(&BOOLS, |facts, present| {
                set_snapshot(&mut facts.baseline, present, BASELINE_AT);
            }),
            dimension(&BOOLS, |facts, present| {
                set_snapshot(&mut facts.terminal, present, TERMINAL_AT);
            }),
            dimension(&services, |facts, value| facts.service = value),
            dimension(&ENDINGS, |facts, value| facts.ending = value),
            // The watchdog agreement: at `D - G` exactly, one below it, or
            // `D` unreadable.
            dimension(&[Some(true), Some(false), None], |facts, reached| {
                facts.watchdog_deadline = reached
                    .and_then(|reached| NonZeroU64::new(TERMINAL_AT + GRACE + u64::from(!reached)));
            }),
            dimension(&OBSERVATIONS[..2], |facts, value| facts.observed = value),
        ],
    );
    assert_eq!(points, 3 * 2 * 2 * 2 * (1 + 11 * 4 * 3) * 9 * 3 * 2);
    assert!(fallbacks > 0);
}

#[test]
fn every_identity_disagreement_is_a_contradiction_and_free_space_is_not() {
    let works = [
        Some(WORK),
        Some(WorkMountFacts {
            mount_id: WORK.mount_id + 1,
            ..WORK
        }),
        Some(WorkMountFacts {
            capacity_bytes: WORK.capacity_bytes + 4096,
            ..WORK
        }),
        None,
    ];
    let afters = [
        Some(WorkStatfsFacts {
            mount: WORK,
            available_bytes: 1_044_480,
        }),
        Some(WorkStatfsFacts {
            mount: WORK,
            available_bytes: 7,
        }),
        None,
    ];
    let barriers = [
        None,
        Some(BarrierFailure::RecheckObservationChanged),
        Some(BarrierFailure::RecheckUnitChanged),
        Some(BarrierFailure::RecheckObservationUnavailable),
    ];
    let (points, _) = exhaust(
        &completed(),
        &[
            dimension(&OBSERVATIONS[..2], |facts, value| facts.observed = value),
            dimension(&BOOLS, |facts, differs| {
                if let Some(unit) = facts.unit.as_mut() {
                    unit.cgroup = if differs { OTHER_CGROUP } else { CGROUP };
                }
            }),
            dimension(&BOOLS, |facts, differs| {
                set_cgroup(&mut facts.baseline, differs);
            }),
            dimension(&BOOLS, |facts, differs| {
                set_cgroup(&mut facts.terminal, differs);
            }),
            dimension(&BOOLS, |facts, differs| {
                with_observation(facts, |invocation, _, _| {
                    *invocation = if differs {
                        OTHER_INVOCATION
                    } else {
                        INVOCATION
                    };
                });
            }),
            dimension(&BOOLS, |facts, differs| {
                with_observation(facts, |_, cgroup, _| {
                    *cgroup = if differs { OTHER_CGROUP } else { CGROUP };
                });
            }),
            dimension(&works, |facts, value| {
                with_observation(facts, |_, _, work| *work = value);
            }),
            dimension(&afters, |facts, value| facts.work_after = value),
            dimension(&barriers, |facts, value| facts.barrier_failure = value),
            dimension(&CANCEL[..2], |facts, value| facts.cancel_source = value),
        ],
    );
    assert_eq!(points, 2 * 2 * 2 * 2 * 2 * 2 * 4 * 3 * 4 * 2);
}

#[test]
fn every_time_order_and_counter_change_is_placed_exactly_once() {
    let relations: [i8; 3] = [-1, 0, 1];
    // The terminal snapshot before, at and after the baseline.
    let times = [BASELINE_AT - 1, BASELINE_AT, BASELINE_AT + 1];
    let mut dimensions = vec![dimension(&times, |facts, at| {
        if let Some(terminal) = facts.terminal.as_mut() {
            terminal.observed_at = at;
        }
    })];
    for index in 0..6 {
        dimensions.push(
            relations
                .iter()
                .map(|&relation| {
                    Box::new(move |facts: &mut TerminationFacts| {
                        set_terminal_counter(facts, index, relation);
                    }) as Setter
                })
                .collect(),
        );
    }
    dimensions.push(dimension(&CANCEL[..2], |facts, value| {
        facts.cancel_source = value;
    }));
    dimensions.push(dimension(
        &[
            Some(ServiceFacts::CLEAN),
            Some(service(
                ServiceResultCode::OomKill,
                MainExitCode::NotExited,
                0,
            )),
        ],
        |facts, value| facts.service = value,
    ));
    let (points, _) = exhaust(&completed(), &dimensions);
    assert_eq!(points, 3 * 729 * 2 * 2);
}

#[test]
fn every_transfer_capture_and_network_class_is_placed_exactly_once() {
    let (points, fallbacks) = exhaust(
        &completed(),
        &[
            dimension(&PROGRESS, |facts, value| facts.progress = value),
            dimension(&BOOLS, |facts, value| facts.input_complete = value),
            dimension(&OUTPUT_TRANSFERS, |facts, value| {
                facts.output_transfer_complete = value;
            }),
            dimension(&CAPTURES, |facts, value| facts.output_capture = value),
            dimension(&FEEDS, |facts, value| facts.adapter_input_complete = value),
            dimension(&NETWORK, |facts, value| {
                facts.local_network_termination = value;
            }),
            dimension(&CANCEL, |facts, value| facts.cancel_source = value),
            dimension(&REQUESTED, |facts, value| facts.requested = value),
        ],
    );
    assert_eq!(points, 3 * 2 * 3 * 5 * 3 * 6 * 3 * 4);
    assert!(fallbacks > 0);
}

/// Realize candidate set `bits` (bit `n - 1` for code `n`) on a released
/// attempt, each code through one witness that adds no other candidate.
fn witness(bits: u16, contradicted: bool) -> TerminationFacts {
    let has = |code: u16| bits & (1 << (code - 1)) != 0;
    let mut facts = completed();
    let mut terminal = COUNTERS;
    facts.cancel_source = has(1).then_some(CancelSource::CancelRequest);
    if has(2) {
        facts.cleanup = CleanupResult::NotProved;
    }
    terminal.oom_kill += u64::from(has(3));
    terminal.memory_max += u64::from(has(4));
    terminal.pids_max += u64::from(has(5));
    if contradicted {
        terminal.throttled_usec -= 1;
    }
    facts.service = Some(match (has(6), has(8)) {
        (false, false) => ServiceFacts::CLEAN,
        (true, false) => service(ServiceResultCode::Timeout, MainExitCode::NotExited, 0),
        (false, true) => service(ServiceResultCode::ExitCode, MainExitCode::Exited, 1),
        (true, true) => service(ServiceResultCode::Timeout, MainExitCode::Exited, 1),
    });
    facts.watchdog_deadline = NonZeroU64::new(TERMINAL_AT + GRACE);
    facts.output_capture = Some(capture(has(7), true));
    facts.local_network_termination =
        has(9).then_some(LocalNetworkTerminationCode::RemoteUnavailable);
    facts.input_complete = !has(10);
    facts.terminal = Some(snapshot(TERMINAL_AT, terminal));
    facts
}

#[test]
fn every_candidate_set_selects_its_strictest_code_unless_contradicted() {
    for bits in 0..1024_u16 {
        for contradicted in BOOLS {
            let facts = witness(bits, contradicted);
            check(&facts);
            let classification = facts.classify();
            let mut expected = bits;
            if contradicted {
                expected = (expected & !0b1_1100) | 0b10;
            }
            for code in CODES {
                assert_eq!(
                    classification.candidates().contains(code),
                    expected & (1 << (code.code() - 1)) != 0,
                    "{bits:#b} {contradicted} {code:?}"
                );
            }
            let strictest = CODES
                .into_iter()
                .find(|code| expected & (1 << (code.code() - 1)) != 0);
            let selected = if contradicted {
                Some(TerminalCode::CleanupFailed)
            } else {
                strictest
            };
            assert_eq!(classification.code(), selected, "{bits:#b} {contradicted}");
        }
    }
}

// ---------------------------------------------------------------------------
// Property tests: concrete values, deterministic seed.

struct SplitMix(u64);

impl SplitMix {
    const fn bits(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    const fn below(&mut self, bound: u64) -> u64 {
        self.bits() % bound
    }

    fn pick<T: Copy>(&mut self, values: &[T]) -> T {
        let index = usize::try_from(self.below(values.len() as u64)).unwrap_or_default();
        values[index]
    }

    const fn flag(&mut self) -> bool {
        self.below(2) == 1
    }

    const fn small(&mut self) -> u64 {
        self.below(4)
    }

    const fn cgroup(&mut self) -> CgroupIdentity {
        CgroupIdentity {
            major: 0,
            minor: 26,
            inode: 5678 + self.below(2),
        }
    }

    const fn counters(&mut self) -> CgroupCounters {
        counters_from([
            self.small(),
            self.small(),
            self.small(),
            self.small(),
            self.small(),
            self.small(),
        ])
    }

    fn snapshot(&mut self) -> Option<CgroupSnapshot> {
        self.flag().then(|| CgroupSnapshot {
            cgroup: self.cgroup(),
            observed_at: BASELINE_AT + self.small(),
            counters: self.counters(),
        })
    }

    const fn work(&mut self) -> WorkMountFacts {
        WorkMountFacts {
            mount_id: 302 + self.below(2),
            capacity_bytes: 4096 * (256 + self.below(2)),
        }
    }

    fn service(&mut self) -> Option<ServiceFacts> {
        self.flag().then(|| ServiceFacts {
            result: self.pick(&RESULTS),
            exec_main_code: self.pick(&EXITS),
            exec_main_status: u8::try_from(self.below(256)).unwrap_or_default(),
        })
    }

    fn observation(&mut self) -> KernelObservationFacts {
        match self.below(3) {
            0 => KernelObservationFacts::Observed {
                invocation_id: self.pick(&[INVOCATION, OTHER_INVOCATION]),
                cgroup: self.cgroup(),
                work: self.flag().then(|| self.work()),
            },
            1 => KernelObservationFacts::NotReached,
            _ => KernelObservationFacts::ObservationFailed,
        }
    }

    fn facts(&mut self) -> TerminationFacts {
        let terminal = self.snapshot();
        let deadline_base = terminal.map_or(TERMINAL_AT, |terminal| terminal.observed_at);
        TerminationFacts {
            progress: self.pick(&PROGRESS),
            launch_failure: self.pick(&LAUNCH),
            start_job: self.pick(&START),
            unit: self.flag().then(|| UnitIdentity {
                invocation_id: self.pick(&[INVOCATION, OTHER_INVOCATION]),
                cgroup: self.cgroup(),
            }),
            baseline: self.snapshot(),
            terminal,
            service: self.service(),
            ending: self.pick(&ENDINGS),
            barrier_failure: self.pick(&BARRIERS),
            input_complete: self.below(8) != 0,
            adapter_input_complete: self.pick(&FEEDS),
            output_capture: self.pick(&CAPTURES),
            output_transfer_complete: self.pick(&OUTPUT_TRANSFERS),
            local_network_termination: self.pick(&NETWORK),
            work_after: self.flag().then(|| WorkStatfsFacts {
                mount: self.work(),
                available_bytes: self.bits(),
            }),
            watchdog_deadline: if self.below(8) == 0 {
                None
            } else {
                NonZeroU64::new(deadline_base + GRACE + self.below(3) - 1)
            },
            cancel_source: self.pick(&CANCEL),
            cleanup: self.pick(&CLEANUP),
            requested: self.pick(&REQUESTED),
            observed: self.observation(),
        }
    }
}

/// Keep every class of `facts` and change its concrete values: shift every
/// time, raise every counter pair equally, rename every identity
/// consistently, move the exit status within its class and change free
/// space.
fn same_class(facts: &TerminationFacts, random: &mut SplitMix) -> TerminationFacts {
    let shift = random.below(1 << 40);
    let raise = random.below(1 << 40);
    let rename = |cgroup: CgroupIdentity| CgroupIdentity {
        major: cgroup.major + 7,
        minor: cgroup.minor ^ 1,
        inode: cgroup.inode + 1_000,
    };
    let invocation = |id: [u8; 16]| id.map(|byte| byte ^ 0x5a);
    let work = |mount: WorkMountFacts| WorkMountFacts {
        mount_id: mount.mount_id + 11,
        capacity_bytes: mount.capacity_bytes * 2,
    };
    let moved = |snapshot: CgroupSnapshot| CgroupSnapshot {
        cgroup: rename(snapshot.cgroup),
        observed_at: snapshot.observed_at + shift,
        counters: counters_from(counter_values(&snapshot.counters).map(|value| value + raise)),
    };
    let mut changed = *facts;
    changed.unit = facts.unit.map(|unit| UnitIdentity {
        invocation_id: invocation(unit.invocation_id),
        cgroup: rename(unit.cgroup),
    });
    changed.baseline = facts.baseline.map(moved);
    changed.terminal = facts.terminal.map(moved);
    changed.watchdog_deadline = facts
        .watchdog_deadline
        .and_then(|deadline| NonZeroU64::new(deadline.get() + shift));
    changed.work_after = facts.work_after.map(|after| WorkStatfsFacts {
        mount: work(after.mount),
        available_bytes: random.bits(),
    });
    changed.service = facts.service.map(|service| ServiceFacts {
        exec_main_status: same_status_class(service.exec_main_status, random),
        ..service
    });
    if let KernelObservationFacts::Observed {
        invocation_id,
        cgroup,
        work: observed_work,
    } = facts.observed
    {
        changed.observed = KernelObservationFacts::Observed {
            invocation_id: invocation(invocation_id),
            cgroup: rename(cgroup),
            work: observed_work.map(work),
        };
    }
    changed
}

fn same_status_class(status: u8, random: &mut SplitMix) -> u8 {
    match status {
        0 | SIGXFSZ => status,
        _ => loop {
            let candidate = u8::try_from(1 + random.below(255)).unwrap_or(1);
            if candidate != SIGXFSZ {
                break candidate;
            }
        },
    }
}

#[test]
fn random_concrete_facts_classify_as_the_oracle_and_only_by_their_class() {
    let mut random = SplitMix(0x0443_0003_c1a5_51f1);
    for _ in 0..20_000 {
        let facts = random.facts();
        check(&facts);
        let changed = same_class(&facts, &mut random);
        check(&changed);
        assert_eq!(
            changed.classify().code(),
            facts.classify().code(),
            "{facts:?}"
        );
        assert_eq!(
            changed.classify().candidates(),
            facts.classify().candidates(),
            "{facts:?}"
        );
        assert_eq!(
            changed.classify().contradiction(),
            facts.classify().contradiction(),
            "{facts:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// R9 §7 vectors, the previously unplaced examples and named rules.

#[test]
fn tme1_a_is_completed() {
    let classification = completed().classify();
    check(&completed());
    assert_eq!(classification.code(), None);
    assert_eq!(classification.contradiction(), None);
    assert!(!classification.quarantined());
    assert_eq!(classification.outcome(), SandboxTerminalOutcome::Completed);
    for code in CODES {
        assert!(!classification.candidates().contains(code));
    }
}

#[test]
fn tme1_b_counter_decrease_forces_cleanup_failed_over_a_cancel() {
    let mut facts = completed();
    let mut baseline = COUNTERS;
    baseline.pids_max = 3;
    let mut terminal = COUNTERS;
    terminal.pids_max = 2;
    facts.baseline = Some(snapshot(BASELINE_AT, baseline));
    facts.terminal = Some(snapshot(TERMINAL_AT, terminal));
    facts.service = Some(service(ServiceResultCode::Signal, MainExitCode::Killed, 9));
    facts.ending = Some(EndingCode::Cancelled);
    facts.cancel_source = Some(CancelSource::CancelRequest);
    facts.output_capture = Some(capture(false, false));
    check(&facts);
    let classification = facts.classify();
    assert_eq!(
        classification.contradiction(),
        Some(Contradiction::CounterDecreased)
    );
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(classification
        .candidates()
        .contains(TerminalCode::Cancelled));
    assert!(classification.quarantined());
    assert_eq!(
        classification.outcome(),
        SandboxTerminalOutcome::UnavailableAfterAdmission
    );
}

#[test]
fn tme1_c_cancel_outranks_a_failed_cleanup_and_still_quarantines() {
    let mut facts = completed();
    facts.service = Some(service(ServiceResultCode::Signal, MainExitCode::Killed, 15));
    facts.ending = Some(EndingCode::Cancelled);
    facts.cancel_source = Some(CancelSource::CancelRequest);
    facts.output_capture = Some(capture(false, false));
    facts.cleanup = CleanupResult::NotProved;
    check(&facts);
    let classification = facts.classify();
    let candidates: Vec<u8> = CODES
        .into_iter()
        .filter(|code| classification.candidates().contains(*code))
        .map(TerminalCode::code)
        .collect();
    assert_eq!(candidates, [1, 2, 8, 10]);
    assert_eq!(classification.code(), Some(TerminalCode::Cancelled));
    assert!(classification.quarantined());
    assert_eq!(classification.outcome(), SandboxTerminalOutcome::Cancelled);
}

#[test]
fn a_revocation_before_the_start_is_cancelled_without_quarantine() {
    let facts = TerminationFacts {
        cancel_source: Some(CancelSource::Revocation),
        cleanup: CleanupResult::NothingCommitted,
        ..unstarted()
    };
    check(&facts);
    let classification = facts.classify();
    assert_eq!(classification.code(), Some(TerminalCode::Cancelled));
    assert_eq!(classification.outcome(), SandboxTerminalOutcome::Cancelled);
    assert!(!classification.quarantined());
}

#[test]
fn a_released_revocation_is_cancelled_like_a_request() {
    let facts = TerminationFacts {
        cancel_source: Some(CancelSource::Revocation),
        service: Some(service(ServiceResultCode::Signal, MainExitCode::Killed, 15)),
        ending: Some(EndingCode::Cancelled),
        ..completed()
    };
    check(&facts);
    assert_eq!(
        facts.classify().outcome(),
        SandboxTerminalOutcome::Cancelled
    );
    assert!(!facts.classify().quarantined());
}

#[test]
fn previously_unplaced_examples_are_protocol_failures() {
    let failed_start = TerminationFacts {
        progress: AttemptProgressCode::StartedNotReleased,
        start_job: Some(StartJobResult::Failed),
        requested: RequestedConfigurationStatus::Verified,
        ..unstarted()
    };
    let root = TerminationFacts {
        launch_failure: Some(LaunchFailure::RootNotActivated),
        ..unstarted()
    };
    let mut cases = vec![failed_start, root];
    for result in [
        ServiceResultCode::Resources,
        ServiceResultCode::Protocol,
        ServiceResultCode::StartLimitHit,
        ServiceResultCode::ExecCondition,
    ] {
        cases.push(TerminationFacts {
            service: Some(service(result, MainExitCode::NotExited, 0)),
            ..completed()
        });
    }
    for facts in cases {
        check(&facts);
        assert_eq!(
            facts.classify().code(),
            Some(TerminalCode::ProtocolFailure),
            "{facts:?}"
        );
    }
}

/// A unit systemd timed out, with both snapshots taken at `terminal_at`.
const fn timed_out(ending: EndingCode, terminal_at: u64, deadline: u64) -> TerminationFacts {
    TerminationFacts {
        baseline: Some(snapshot(terminal_at, COUNTERS)),
        terminal: Some(snapshot(terminal_at, COUNTERS)),
        service: Some(service(ServiceResultCode::Timeout, MainExitCode::Killed, 9)),
        ending: Some(ending),
        watchdog_deadline: NonZeroU64::new(deadline),
        ..completed()
    }
}

#[test]
fn the_watchdog_needs_systemd_timeout_at_or_after_d_minus_g() {
    assert_eq!(WATCHDOG_GRACE_NS, GRACE);
    let deadline = TERMINAL_AT + GRACE;
    for ending in [
        EndingCode::CgroupEmpty,
        EndingCode::WatchdogKilled,
        EndingCode::WatchdogKillFailed,
    ] {
        let at = timed_out(ending, TERMINAL_AT, deadline);
        let below = timed_out(ending, TERMINAL_AT, deadline + 1);
        check(&at);
        check(&below);
        assert_eq!(at.classify().code(), Some(TerminalCode::Watchdog));
        assert!(!at.classify().quarantined());
        assert_eq!(below.classify().code(), Some(TerminalCode::CleanupFailed));
    }
    // `D < G`: the agreement holds for every terminal time.
    let early = timed_out(EndingCode::CgroupEmpty, 0, GRACE / 2);
    check(&early);
    assert_eq!(early.classify().code(), Some(TerminalCode::Watchdog));
}

#[test]
fn a_broker_kill_without_a_systemd_timeout_is_an_enforcement_failure() {
    let facts = TerminationFacts {
        service: Some(service(ServiceResultCode::Signal, MainExitCode::Killed, 9)),
        ending: Some(EndingCode::WatchdogKilled),
        ..completed()
    };
    check(&facts);
    assert_eq!(facts.classify().code(), Some(TerminalCode::CleanupFailed));
}

#[test]
fn a_timeout_before_any_cgroup_was_bound_follows_the_r9_rows() {
    let unbound = |start_job| TerminationFacts {
        progress: AttemptProgressCode::StartedNotReleased,
        start_job: Some(start_job),
        unit: None,
        baseline: None,
        terminal: None,
        service: Some(service(
            ServiceResultCode::Timeout,
            MainExitCode::NotExited,
            0,
        )),
        ending: None,
        work_after: None,
        observed: KernelObservationFacts::NotReached,
        ..completed()
    };
    // A start job that timed out is a protocol failure, not missing evidence.
    let timed_out_start = unbound(StartJobResult::Timeout);
    check(&timed_out_start);
    let classification = timed_out_start.classify();
    assert_eq!(classification.code(), Some(TerminalCode::ProtocolFailure));
    assert!(!classification.quarantined());
    // A started unit that timed out unreleased places nowhere: the fallback.
    let unplaced = unbound(StartJobResult::Done);
    assert!(check(&unplaced));
    let classification = unplaced.classify();
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(!classification
        .candidates()
        .contains(TerminalCode::CleanupFailed));
    assert!(!classification.candidates().contains(TerminalCode::Watchdog));
    assert!(classification.quarantined());
}

#[test]
fn work_free_space_is_never_compared() {
    let mut facts = completed();
    facts.work_after = Some(WorkStatfsFacts {
        mount: WORK,
        available_bytes: 0,
    });
    check(&facts);
    assert_eq!(facts.classify().code(), None);
    facts.work_after = Some(WorkStatfsFacts {
        mount: WorkMountFacts {
            capacity_bytes: WORK.capacity_bytes + 4096,
            ..WORK
        },
        available_bytes: 0,
    });
    check(&facts);
    assert_eq!(
        facts.classify().contradiction(),
        Some(Contradiction::IdentityChanged)
    );
}

#[test]
fn a_sigxfsz_crash_is_a_file_limit_and_cpu_throttling_is_never_terminal() {
    let facts = TerminationFacts {
        service: Some(service(
            ServiceResultCode::Signal,
            MainExitCode::Killed,
            SIGXFSZ,
        )),
        ..completed()
    };
    check(&facts);
    assert_eq!(
        facts.classify().code(),
        Some(TerminalCode::FileOrOutputLimit)
    );
    let throttled = TerminationFacts {
        terminal: Some(snapshot(
            TERMINAL_AT,
            CgroupCounters {
                nr_throttled: 50,
                throttled_usec: 9_000,
                ..COUNTERS
            },
        )),
        ..completed()
    };
    check(&throttled);
    assert_eq!(throttled.classify().code(), None);
}

#[test]
fn every_coded_field_keeps_its_r9_number() {
    let numbers: [(u8, u8); 68] = [
        (AttemptProgressCode::NotStarted as u8, 0),
        (AttemptProgressCode::StartedNotReleased as u8, 1),
        (AttemptProgressCode::Released as u8, 2),
        (LaunchFailure::RootNotActivated as u8, 0),
        (LaunchFailure::PreStartRecheckFailed as u8, 1),
        (LaunchFailure::UnitRefFailed as u8, 2),
        (LaunchFailure::OutputReservationRefused as u8, 3),
        (LaunchFailure::StdioChannelFailed as u8, 4),
        (LaunchFailure::AdmissionClosed as u8, 5),
        (StartJobResult::Done as u8, 0),
        (StartJobResult::Canceled as u8, 1),
        (StartJobResult::Timeout as u8, 2),
        (StartJobResult::Failed as u8, 3),
        (StartJobResult::Dependency as u8, 4),
        (StartJobResult::Skipped as u8, 5),
        (Contradiction::IdentityChanged as u8, 0),
        (Contradiction::TimeReversed as u8, 1),
        (Contradiction::CounterDecreased as u8, 2),
        (ServiceResultCode::Success as u8, 0),
        (ServiceResultCode::Resources as u8, 1),
        (ServiceResultCode::Protocol as u8, 2),
        (ServiceResultCode::Timeout as u8, 3),
        (ServiceResultCode::ExitCode as u8, 4),
        (ServiceResultCode::Signal as u8, 5),
        (ServiceResultCode::CoreDump as u8, 6),
        (ServiceResultCode::Watchdog as u8, 7),
        (ServiceResultCode::StartLimitHit as u8, 8),
        (ServiceResultCode::OomKill as u8, 9),
        (ServiceResultCode::ExecCondition as u8, 10),
        (MainExitCode::NotExited as u8, 0),
        (MainExitCode::Exited as u8, 1),
        (MainExitCode::Killed as u8, 2),
        (MainExitCode::Dumped as u8, 3),
        (EndingCode::CgroupEmpty as u8, 0),
        (EndingCode::WatchdogKilled as u8, 1),
        (EndingCode::WatchdogKillFailed as u8, 2),
        (EndingCode::ProtocolFailureKilled as u8, 3),
        (EndingCode::ProtocolFailureKillFailed as u8, 4),
        (EndingCode::Cancelled as u8, 5),
        (EndingCode::CancelledWatchdogKilled as u8, 6),
        (EndingCode::CancelledWatchdogKillFailed as u8, 7),
        (BarrierFailure::ReadyUnavailable as u8, 0),
        (BarrierFailure::ReadyFraming as u8, 1),
        (BarrierFailure::ReadyPidMismatch as u8, 2),
        (BarrierFailure::ReadyMalformed as u8, 3),
        (BarrierFailure::ReadyMismatch as u8, 4),
        (BarrierFailure::RecheckAuthority as u8, 5),
        (BarrierFailure::RecheckObservationUnavailable as u8, 6),
        (BarrierFailure::RecheckObservationChanged as u8, 7),
        (BarrierFailure::RecheckIdentityUnreadable as u8, 8),
        (BarrierFailure::RecheckExecutableUnreadable as u8, 9),
        (BarrierFailure::RecheckExpired as u8, 10),
        (BarrierFailure::RecheckUnitChanged as u8, 11),
        (BarrierFailure::ReleaseSend as u8, 12),
        (LocalNetworkTerminationCode::RemoteUnavailable as u8, 0),
        (LocalNetworkTerminationCode::DigestMismatch as u8, 1),
        (LocalNetworkTerminationCode::ProtocolFailure as u8, 2),
        (LocalNetworkTerminationCode::CaptureFailure as u8, 3),
        (LocalNetworkTerminationCode::ChannelFailure as u8, 4),
        (CancelSource::CancelRequest as u8, 0),
        (CancelSource::Revocation as u8, 1),
        (CleanupResult::Proved as u8, 0),
        (CleanupResult::NotProved as u8, 1),
        (CleanupResult::NothingCommitted as u8, 2),
        (RequestedConfigurationStatus::Verified as u8, 0),
        (RequestedConfigurationStatus::NotRequested as u8, 1),
        (RequestedConfigurationStatus::Mismatch as u8, 2),
        (RequestedConfigurationStatus::ReadbackUnavailable as u8, 3),
    ];
    for (index, (found, literal)) in numbers.into_iter().enumerate() {
        assert_eq!(found, literal, "entry {index}");
    }
    let codes: Vec<u8> = CODES.into_iter().map(TerminalCode::code).collect();
    assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn snapshots_without_a_unit_are_missing_evidence_even_when_cancelled() {
    for (baseline, terminal) in [(true, true), (true, false), (false, true)] {
        let unbound = TerminationFacts {
            progress: AttemptProgressCode::StartedNotReleased,
            unit: None,
            baseline: baseline.then_some(snapshot(BASELINE_AT, COUNTERS)),
            terminal: terminal.then_some(snapshot(TERMINAL_AT, COUNTERS)),
            service: None,
            ending: None,
            work_after: None,
            observed: KernelObservationFacts::NotReached,
            ..completed()
        };
        let cancelled = TerminationFacts {
            cancel_source: Some(CancelSource::CancelRequest),
            ..unbound
        };
        check(&cancelled);
        let classification = cancelled.classify();
        assert_eq!(classification.code(), Some(TerminalCode::Cancelled));
        assert!(classification
            .candidates()
            .contains(TerminalCode::CleanupFailed));
        assert!(classification.quarantined());
        let failed_start = TerminationFacts {
            start_job: Some(StartJobResult::Failed),
            ..unbound
        };
        check(&failed_start);
        assert_eq!(
            failed_start.classify().code(),
            Some(TerminalCode::CleanupFailed)
        );
    }
}

#[test]
fn the_watchdog_agreement_saturates_instead_of_overflowing() {
    let cases = [
        (u64::MAX, u64::MAX, TerminalCode::Watchdog),
        (u64::MAX - GRACE, u64::MAX, TerminalCode::Watchdog),
        (u64::MAX - GRACE - 1, u64::MAX, TerminalCode::CleanupFailed),
        (u64::MAX - 1, GRACE / 2, TerminalCode::Watchdog),
        (u64::MAX, 1, TerminalCode::Watchdog),
    ];
    for (terminal_at, deadline, code) in cases {
        let facts = timed_out(EndingCode::CgroupEmpty, terminal_at, deadline);
        check(&facts);
        assert_eq!(facts.classify().code(), Some(code), "{facts:?}");
    }
}

#[test]
fn an_unreadable_activation_is_missing_evidence_once_a_unit_exists() {
    assert_eq!(attempt_watchdog_deadline(0, 5_000), None);
    assert_eq!(attempt_watchdog_deadline(0, 0), None);
    assert_eq!(attempt_watchdog_deadline(u64::MAX, 1), None);
    assert_eq!(attempt_watchdog_deadline(7, 5), NonZeroU64::new(12));
    assert_eq!(attempt_watchdog_deadline(7, 0), NonZeroU64::new(7));
    assert_eq!(
        attempt_watchdog_deadline(u64::MAX, 0),
        NonZeroU64::new(u64::MAX)
    );
    // A zero activation would otherwise read as `D = 0`: always reached.
    let zero = TerminationFacts {
        watchdog_deadline: attempt_watchdog_deadline(0, DEADLINE),
        ..timed_out(EndingCode::CgroupEmpty, TERMINAL_AT, DEADLINE)
    };
    check(&zero);
    let classification = zero.classify();
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(!classification.candidates().contains(TerminalCode::Watchdog));
    let completed_otherwise = TerminationFacts {
        watchdog_deadline: None,
        ..completed()
    };
    check(&completed_otherwise);
    let classification = completed_otherwise.classify();
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(classification
        .candidates()
        .contains(TerminalCode::CleanupFailed));
    // A failed start job may leave the activation unset: no `D`, still the
    // protocol failure R9 row 10 names, with no missing evidence.
    let failed_start = TerminationFacts {
        progress: AttemptProgressCode::StartedNotReleased,
        start_job: Some(StartJobResult::Failed),
        watchdog_deadline: None,
        service: None,
        ending: None,
        output_capture: None,
        ..completed()
    };
    check(&failed_start);
    let classification = failed_start.classify();
    assert_eq!(classification.code(), Some(TerminalCode::ProtocolFailure));
    assert!(!classification.quarantined());
    // Before any unit, `D` never selects a code.
    let revoked = TerminationFacts {
        watchdog_deadline: None,
        cancel_source: Some(CancelSource::Revocation),
        cleanup: CleanupResult::NothingCommitted,
        ..unstarted()
    };
    check(&revoked);
    assert!(!revoked.classify().quarantined());
    assert_eq!(revoked.classify().code(), Some(TerminalCode::Cancelled));
}

/// Make the terminal snapshot contradict the baseline: 0 none, 1 identity,
/// 2 time, 3 a telemetry counter going down.
const fn contradict(facts: &mut TerminationFacts, kind: u8) {
    if let Some(terminal) = facts.terminal.as_mut() {
        match kind {
            1 => terminal.cgroup = OTHER_CGROUP,
            2 => terminal.observed_at = BASELINE_AT - 1,
            3 => terminal.counters.throttled_usec -= 1,
            _ => {}
        }
    }
}

#[test]
fn every_service_ending_cleanup_cancel_and_contradiction_is_placed_exactly_once() {
    let services = services();
    let (points, fallbacks) = exhaust(
        &completed(),
        &[
            dimension(&services, |facts, value| facts.service = value),
            dimension(&ENDINGS, |facts, value| facts.ending = value),
            dimension(&CLEANUP, |facts, value| facts.cleanup = value),
            dimension(&CANCEL, |facts, value| facts.cancel_source = value),
            dimension(&[0_u8, 1, 2, 3], contradict),
        ],
    );
    assert_eq!(points, (1 + 11 * 4 * 3) * 9 * 3 * 3 * 4);
    assert!(fallbacks > 0);
}

#[cfg(target_os = "linux")]
#[test]
fn local_network_terminations_keep_their_codes() {
    use pos_reference::sandbox_provider_protocol::LocalNetworkTermination;
    let pairs = [
        (
            LocalNetworkTermination::RemoteUnavailable,
            LocalNetworkTerminationCode::RemoteUnavailable,
        ),
        (
            LocalNetworkTermination::DigestMismatch,
            LocalNetworkTerminationCode::DigestMismatch,
        ),
        (
            LocalNetworkTermination::ProtocolFailure,
            LocalNetworkTerminationCode::ProtocolFailure,
        ),
        (
            LocalNetworkTermination::CaptureFailure,
            LocalNetworkTerminationCode::CaptureFailure,
        ),
        (
            LocalNetworkTermination::ChannelFailure,
            LocalNetworkTerminationCode::ChannelFailure,
        ),
    ];
    for (termination, code) in pairs {
        assert_eq!(LocalNetworkTerminationCode::from(termination), code);
    }
}

/// The candidate codes of `facts`, in precedence order.
fn candidate_codes(facts: &TerminationFacts) -> Vec<u8> {
    let classification = facts.classify();
    CODES
        .into_iter()
        .filter(|code| classification.candidates().contains(*code))
        .map(TerminalCode::code)
        .collect()
}

#[test]
fn r10_feed_capture_and_pre_start_rows_select_their_codes() {
    // TME1-D: one byte over the ceiling, and the adapter exited 1.
    let over = TerminationFacts {
        output_capture: Some(capture(true, false)),
        service: Some(service(
            ServiceResultCode::ExitCode,
            MainExitCode::Exited,
            1,
        )),
        ..completed()
    };
    // TME1-E: the stdin feed stopped early (`EPIPE`).
    let short_feed = TerminationFacts {
        adapter_input_complete: Some(false),
        ..completed()
    };
    // A released attempt with no `adapter-input` lacks evidence.
    let no_feed = TerminationFacts {
        adapter_input_complete: None,
        ..completed()
    };
    let launch = |failure| TerminationFacts {
        launch_failure: Some(failure),
        ..unstarted()
    };
    for (facts, candidates, quarantined) in [
        (over, vec![7, 8], false),
        (short_feed, vec![10], false),
        (no_feed, vec![2], true),
        // TME1-F: the aggregate ledger refused the output reservation.
        (
            launch(LaunchFailure::OutputReservationRefused),
            vec![10],
            false,
        ),
        (launch(LaunchFailure::StdioChannelFailed), vec![9], false),
        (launch(LaunchFailure::AdmissionClosed), vec![2], true),
    ] {
        check(&facts);
        assert_eq!(candidate_codes(&facts), candidates, "{facts:?}");
        let classification = facts.classify();
        assert_eq!(
            classification.code().map(TerminalCode::code),
            candidates.first().copied(),
            "{facts:?}"
        );
        assert_eq!(classification.quarantined(), quarantined, "{facts:?}");
    }
}
