//! Every provider ending and unit result keeps its closed R9 code.

use pos_reference::sandbox_provider_protocol::termination::{
    EndingCode, MainExitCode, ServiceFacts, ServiceResultCode,
};

use super::service_facts;
use crate::{AttemptEnding, SystemdMainExit, SystemdServiceResult};

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
fn every_main_exit_keeps_its_exec_main_code_and_status() {
    let cases = [
        (SystemdMainExit::NotRecorded, MainExitCode::NotExited, 0),
        (
            SystemdMainExit::Exited { status: 3 },
            MainExitCode::Exited,
            3,
        ),
        (
            SystemdMainExit::Killed { signal: 25 },
            MainExitCode::Killed,
            25,
        ),
        (
            SystemdMainExit::Dumped { signal: 11 },
            MainExitCode::Dumped,
            11,
        ),
    ];
    for (main, exec_main_code, exec_main_status) in cases {
        assert_eq!(
            service_facts(SystemdServiceResult::Signal, main),
            ServiceFacts {
                result: ServiceResultCode::Signal,
                exec_main_code,
                exec_main_status,
            }
        );
    }
    assert_eq!(
        service_facts(
            SystemdServiceResult::Success,
            SystemdMainExit::Exited { status: 0 }
        ),
        ServiceFacts::CLEAN
    );
}
