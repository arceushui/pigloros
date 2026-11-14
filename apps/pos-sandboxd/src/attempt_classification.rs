//! The provider's evidence in the closed codes of the ADR-069 R9 classifier.
//!
//! The terminal classifier is [`TerminationFacts::classify`] in
//! `pos-reference`, shared with every verifier that recomputes a TME1. These
//! conversions give it the codes of the evidence the provider already holds:
//! how a released attempt ended, and the unit's `Result` and main exit.
//!
//! [`TerminationFacts::classify`]: pos_reference::sandbox_provider_protocol::termination::TerminationFacts::classify

use pos_reference::sandbox_provider_protocol::termination::{
    EndingCode, MainExitCode, ServiceFacts, ServiceResultCode,
};

use crate::{AttemptEnding, SystemdMainExit, SystemdServiceResult};

impl From<AttemptEnding> for EndingCode {
    fn from(ending: AttemptEnding) -> Self {
        match ending {
            AttemptEnding::CgroupEmpty => Self::CgroupEmpty,
            AttemptEnding::WatchdogKilled => Self::WatchdogKilled,
            AttemptEnding::WatchdogKillFailed => Self::WatchdogKillFailed,
            AttemptEnding::ProtocolFailureKilled => Self::ProtocolFailureKilled,
            AttemptEnding::ProtocolFailureKillFailed => Self::ProtocolFailureKillFailed,
            AttemptEnding::Cancelled { watchdog: None } => Self::Cancelled,
            AttemptEnding::Cancelled {
                watchdog: Some(true),
            } => Self::CancelledWatchdogKilled,
            AttemptEnding::Cancelled {
                watchdog: Some(false),
            } => Self::CancelledWatchdogKillFailed,
        }
    }
}

impl From<SystemdServiceResult> for ServiceResultCode {
    fn from(result: SystemdServiceResult) -> Self {
        match result {
            SystemdServiceResult::Success => Self::Success,
            SystemdServiceResult::Resources => Self::Resources,
            SystemdServiceResult::Protocol => Self::Protocol,
            SystemdServiceResult::Timeout => Self::Timeout,
            SystemdServiceResult::ExitCode => Self::ExitCode,
            SystemdServiceResult::Signal => Self::Signal,
            SystemdServiceResult::CoreDump => Self::CoreDump,
            SystemdServiceResult::Watchdog => Self::Watchdog,
            SystemdServiceResult::StartLimitHit => Self::StartLimitHit,
            SystemdServiceResult::OomKill => Self::OomKill,
            SystemdServiceResult::ExecCondition => Self::ExecCondition,
        }
    }
}

/// TME1 `service` for a unit's `Result` and the main exit systemd recorded:
/// `ExecMainCode` 0 to 3 with the exit status or the signal number.
#[must_use]
pub fn service_facts(result: SystemdServiceResult, main: SystemdMainExit) -> ServiceFacts {
    let (exec_main_code, exec_main_status) = match main {
        SystemdMainExit::NotRecorded => (MainExitCode::NotExited, 0),
        SystemdMainExit::Exited { status } => (MainExitCode::Exited, status),
        SystemdMainExit::Killed { signal } => (MainExitCode::Killed, signal),
        SystemdMainExit::Dumped { signal } => (MainExitCode::Dumped, signal),
    };
    ServiceFacts {
        result: result.into(),
        exec_main_code,
        exec_main_status,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
