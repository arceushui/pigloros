//! The provider's evidence in the closed codes of the ADR-069 R9 classifier.
//!
//! The terminal classifier is [`TerminationFacts::classify`] in
//! `pos-reference`, shared with every verifier that recomputes a TME1. These
//! conversions give it the codes of the evidence the provider already holds:
//! how a released attempt ended, and the unit's `Result` and main exit code.
//! A refused output reservation converts to its `launch-failure` in
//! `pos-reference`.
//! The lifecycle assembles the facts when it emits the terminal records.
//!
//! [`TerminationFacts::classify`]: pos_reference::sandbox_provider_protocol::TerminationFacts::classify

use pos_reference::sandbox_provider_protocol::{EndingCode, MainExitCode, ServiceResultCode};

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

/// TME1 `service.exec-main-code`; `exec-main-status` is the exit status or
/// signal number the variant carries.
impl From<SystemdMainExit> for MainExitCode {
    fn from(main: SystemdMainExit) -> Self {
        match main {
            SystemdMainExit::NotRecorded => Self::NotExited,
            SystemdMainExit::Exited { .. } => Self::Exited,
            SystemdMainExit::Killed { .. } => Self::Killed,
            SystemdMainExit::Dumped { .. } => Self::Dumped,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
