//! Every provider ending and unit result keeps its closed R9 code.

use pos_reference::sandbox_provider_protocol::{
    EndingCode, LaunchFailure, MainExitCode, ServiceResultCode,
};

use crate::{AttemptEnding, OutputReservationRefused, SystemdMainExit, SystemdServiceResult};

#[test]
fn a_refused_output_reservation_keeps_its_launch_failure() {
    // R10 §4.7: a full ledger is code 3 (candidate 10), a closed one code 5
    // (candidate 2, quarantine).
    assert_eq!(
        LaunchFailure::from(OutputReservationRefused::AggregateExceeded),
        LaunchFailure::OutputReservationRefused
    );
    assert_eq!(
        LaunchFailure::from(OutputReservationRefused::AdmissionClosed),
        LaunchFailure::AdmissionClosed
    );
}

#[test]
fn every_attempt_ending_keeps_its_tme1_code() {
    let pairs = [
        (AttemptEnding::CgroupEmpty, EndingCode::CgroupEmpty),
        (AttemptEnding::WatchdogKilled, EndingCode::WatchdogKilled),
        (
            AttemptEnding::WatchdogKillFailed,
            EndingCode::WatchdogKillFailed,
        ),
        (
            AttemptEnding::ProtocolFailureKilled,
            EndingCode::ProtocolFailureKilled,
        ),
        (
            AttemptEnding::ProtocolFailureKillFailed,
            EndingCode::ProtocolFailureKillFailed,
        ),
        (
            AttemptEnding::Cancelled { watchdog: None },
            EndingCode::Cancelled,
        ),
        (
            AttemptEnding::Cancelled {
                watchdog: Some(true),
            },
            EndingCode::CancelledWatchdogKilled,
        ),
        (
            AttemptEnding::Cancelled {
                watchdog: Some(false),
            },
            EndingCode::CancelledWatchdogKillFailed,
        ),
    ];
    for (ending, code) in pairs {
        assert_eq!(EndingCode::from(ending), code);
    }
}

#[test]
fn every_service_result_keeps_its_tme1_code() {
    let pairs = [
        (SystemdServiceResult::Success, ServiceResultCode::Success),
        (
            SystemdServiceResult::Resources,
            ServiceResultCode::Resources,
        ),
        (SystemdServiceResult::Protocol, ServiceResultCode::Protocol),
        (SystemdServiceResult::Timeout, ServiceResultCode::Timeout),
        (SystemdServiceResult::ExitCode, ServiceResultCode::ExitCode),
        (SystemdServiceResult::Signal, ServiceResultCode::Signal),
        (SystemdServiceResult::CoreDump, ServiceResultCode::CoreDump),
        (SystemdServiceResult::Watchdog, ServiceResultCode::Watchdog),
        (
            SystemdServiceResult::StartLimitHit,
            ServiceResultCode::StartLimitHit,
        ),
        (SystemdServiceResult::OomKill, ServiceResultCode::OomKill),
        (
            SystemdServiceResult::ExecCondition,
            ServiceResultCode::ExecCondition,
        ),
    ];
    for (result, code) in pairs {
        assert_eq!(ServiceResultCode::from(result), code);
    }
}

#[test]
fn every_main_exit_keeps_its_exec_main_code() {
    let cases = [
        (SystemdMainExit::NotRecorded, MainExitCode::NotExited),
        (SystemdMainExit::Exited { status: 3 }, MainExitCode::Exited),
        (SystemdMainExit::Killed { signal: 25 }, MainExitCode::Killed),
        (SystemdMainExit::Dumped { signal: 11 }, MainExitCode::Dumped),
    ];
    for (main, code) in cases {
        assert_eq!(MainExitCode::from(main), code);
    }
}
