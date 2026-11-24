//! The provider-neutral Sandbox Provider conformance suite (ADR-069 §9, #216).
//!
//! The suite names every case a provider must pass before first production
//! use, the public outcome it must show for each, and the report that a
//! disposable-VM run produces. A case's outcome is stated only in the closed
//! SPY1/SPE1 vocabulary ([`SandboxTerminalOutcomeV1`], the SAU1 terminal
//! event codes `1..=10` and [`SandboxProviderErrorCodeV1`]), so the same
//! suite gates the systemd provider today and any replacement later.
//!
//! A provider is bound through [`ProviderUnderTest`]; this module holds no
//! launcher, adapter fixture or host access. The binding for the selected
//! systemd provider runs in the pinned QEMU guest and hands the observed
//! public results to [`run_suite`]. Fixture adapters exit zero only when every
//! forbidden operation they attempt was denied, so a contained adapter is a
//! `Completed` attempt and any other outcome is a failure of containment.

use serde::{Deserialize, Serialize};

use crate::{
    SandboxArchitectureV1, SandboxProviderErrorCodeV1, SandboxProviderErrorV1,
    SandboxProviderResultV1, SandboxTerminalOutcomeV1,
};

/// Attempts that run at once in [`ProviderConformanceCase::ConcurrentAttempts`].
pub const CONCURRENT_ATTEMPTS_V1: usize = 8;

/// SAU1 terminal event code of a cancelled attempt (ADR-069 §8).
const CANCELLED: u8 = 1;
const OOM_KILLED: u8 = 3;
const MEMORY_LIMIT: u8 = 4;
const TASK_LIMIT: u8 = 5;
const WATCHDOG: u8 = 6;
const FILE_OR_OUTPUT_LIMIT: u8 = 7;
const PROCESS_CRASH: u8 = 8;
const PROTOCOL_FAILURE: u8 = 10;
/// The greatest SAU1 terminal event code; codes above it are lifecycle events.
const LAST_TERMINAL_CODE: u8 = 10;
/// Every terminal code an `UnavailableAfterAdmission` result may end with.
const UNAVAILABLE_CODES: [u8; 9] = [2, 3, 4, 5, 6, 7, 8, 9, 10];

/// One conformance case. Its [`id`](Self::id) is the stable report name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProviderConformanceCase {
    /// The adapter opens host paths and writes outside its work area.
    FilesystemEscape,
    /// The adapter writes to its read-only root.
    ReadOnlyRootWrite,
    /// The adapter writes past its work-area capacity.
    WorkAreaExhaustion,
    /// The adapter opens raw, UDP, Unix and undeclared TCP sockets and DNS.
    NetworkEscape,
    /// The adapter signals and traces processes outside itself.
    ForeignSignals,
    /// The adapter leaves a daemonized child behind and exits.
    OrphanedChild,
    /// The adapter forks past the task ceiling.
    TaskExhaustion,
    /// The adapter allocates past the memory ceiling.
    MemoryExhaustion,
    /// The adapter runs past the watchdog.
    WatchdogExpiry,
    /// The adapter emits more output than the output ceiling.
    OversizedOutput,
    /// The adapter exits unsuccessfully.
    AdapterCrash,
    /// The adapter emits a malformed output frame.
    MalformedOutput,
    /// An authenticated cancel arrives before the adapter is released.
    CancelBeforeRelease,
    /// An authenticated cancel arrives while the adapter runs.
    CancelWhileRunning,
    /// The broker is killed mid-attempt and restarted.
    BrokerCrashRecovery,
    /// The provider's trust is revoked before admission.
    RevokedBeforeAdmission,
    /// The provider's trust is revoked while an attempt runs.
    RevokedWhileRunning,
    /// A required host feature is missing.
    MissingHostFeature,
    /// [`CONCURRENT_ATTEMPTS_V1`] honest attempts run at once.
    ConcurrentAttempts,
}

/// The public outcome a conforming provider shows for a case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedPublicOutcome {
    /// An SPY1 result with this outcome and one of these terminal event codes
    /// (none when the slice is empty).
    Terminal {
        /// The closed SPY1 outcome.
        outcome: SandboxTerminalOutcomeV1,
        /// The accepted SAU1 terminal event codes.
        codes: &'static [u8],
    },
    /// An SPE1 refusal with this code.
    Refused(SandboxProviderErrorCodeV1),
}

const fn contained() -> ExpectedPublicOutcome {
    ExpectedPublicOutcome::Terminal {
        outcome: SandboxTerminalOutcomeV1::Completed,
        codes: &[],
    }
}

const fn unavailable(codes: &'static [u8]) -> ExpectedPublicOutcome {
    ExpectedPublicOutcome::Terminal {
        outcome: SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
        codes,
    }
}

const fn cancelled() -> ExpectedPublicOutcome {
    ExpectedPublicOutcome::Terminal {
        outcome: SandboxTerminalOutcomeV1::Cancelled,
        codes: &[CANCELLED],
    }
}

impl ProviderConformanceCase {
    /// Every case, in report order.
    pub const ALL: [Self; 19] = [
        Self::FilesystemEscape,
        Self::ReadOnlyRootWrite,
        Self::WorkAreaExhaustion,
        Self::NetworkEscape,
        Self::ForeignSignals,
        Self::OrphanedChild,
        Self::TaskExhaustion,
        Self::MemoryExhaustion,
        Self::WatchdogExpiry,
        Self::OversizedOutput,
        Self::AdapterCrash,
        Self::MalformedOutput,
        Self::CancelBeforeRelease,
        Self::CancelWhileRunning,
        Self::BrokerCrashRecovery,
        Self::RevokedBeforeAdmission,
        Self::RevokedWhileRunning,
        Self::MissingHostFeature,
        Self::ConcurrentAttempts,
    ];

    /// The stable report name.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::FilesystemEscape => "filesystem-escape",
            Self::ReadOnlyRootWrite => "read-only-root-write",
            Self::WorkAreaExhaustion => "work-area-exhaustion",
            Self::NetworkEscape => "network-escape",
            Self::ForeignSignals => "foreign-signals",
            Self::OrphanedChild => "orphaned-child",
            Self::TaskExhaustion => "task-exhaustion",
            Self::MemoryExhaustion => "memory-exhaustion",
            Self::WatchdogExpiry => "watchdog-expiry",
            Self::OversizedOutput => "oversized-output",
            Self::AdapterCrash => "adapter-crash",
            Self::MalformedOutput => "malformed-output",
            Self::CancelBeforeRelease => "cancel-before-release",
            Self::CancelWhileRunning => "cancel-while-running",
            Self::BrokerCrashRecovery => "broker-crash-recovery",
            Self::RevokedBeforeAdmission => "revoked-before-admission",
            Self::RevokedWhileRunning => "revoked-while-running",
            Self::MissingHostFeature => "missing-host-feature",
            Self::ConcurrentAttempts => "concurrent-attempts",
        }
    }

    /// The case with this report name, if any.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|case| case.id() == id)
    }

    /// How many attempts the case runs at once.
    #[must_use]
    pub const fn attempts(self) -> usize {
        match self {
            Self::ConcurrentAttempts => CONCURRENT_ATTEMPTS_V1,
            _ => 1,
        }
    }

    /// The public outcome every attempt of the case must show (ADR-069 §8).
    ///
    /// Memory exhaustion accepts both OOM and memory-ceiling codes: which one
    /// the kernel reports first is not a provider-neutral property.
    #[must_use]
    pub const fn expectation(self) -> ExpectedPublicOutcome {
        match self {
            Self::FilesystemEscape
            | Self::ReadOnlyRootWrite
            | Self::NetworkEscape
            | Self::ForeignSignals
            | Self::OrphanedChild
            | Self::ConcurrentAttempts => contained(),
            Self::WorkAreaExhaustion | Self::OversizedOutput => {
                unavailable(&[FILE_OR_OUTPUT_LIMIT])
            }
            Self::TaskExhaustion => unavailable(&[TASK_LIMIT]),
            Self::MemoryExhaustion => unavailable(&[OOM_KILLED, MEMORY_LIMIT]),
            Self::WatchdogExpiry => unavailable(&[WATCHDOG]),
            Self::AdapterCrash => unavailable(&[PROCESS_CRASH]),
            Self::MalformedOutput => unavailable(&[PROTOCOL_FAILURE]),
            Self::CancelBeforeRelease | Self::CancelWhileRunning | Self::RevokedWhileRunning => {
                cancelled()
            }
            // The restarted broker proves cleanup of the interrupted attempt
            // and reports it unavailable; which terminal code the kernel
            // evidence selects after the crash is not fixed.
            Self::BrokerCrashRecovery => unavailable(&UNAVAILABLE_CODES),
            Self::RevokedBeforeAdmission => {
                ExpectedPublicOutcome::Refused(SandboxProviderErrorCodeV1::TrustRevoked)
            }
            Self::MissingHostFeature => ExpectedPublicOutcome::Terminal {
                outcome: SandboxTerminalOutcomeV1::UnavailableBeforeAdmission,
                codes: &[],
            },
        }
    }
}

/// The public outcome of one observed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedPublic {
    /// An SPY1 result.
    Terminal {
        /// Its closed outcome.
        outcome: SandboxTerminalOutcomeV1,
        /// Its terminal SAU1 event code, when its event list ends with one.
        terminal_code: Option<u8>,
    },
    /// An SPE1 refusal.
    Refused(SandboxProviderErrorCodeV1),
}

/// One attempt's public outcome and identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedAttempt {
    /// The attempt identity the provider answered for, when it named one.
    pub attempt_id: Option<[u8; 16]>,
    /// The public outcome.
    pub public: ObservedPublic,
}

impl ObservedAttempt {
    /// Read an SPY1 result: the terminal code is its last event when that
    /// event is a terminal code (`..=10`), because lifecycle codes precede it.
    #[must_use]
    pub fn from_result(result: &SandboxProviderResultV1) -> Self {
        let terminal_code = result
            .operational_events
            .last()
            .and_then(|code| u8::try_from(*code).ok())
            .filter(|code| *code <= LAST_TERMINAL_CODE);
        Self {
            attempt_id: Some(result.attempt_id),
            public: ObservedPublic::Terminal {
                outcome: result.outcome,
                terminal_code,
            },
        }
    }

    /// Read an SPE1 refusal.
    #[must_use]
    pub const fn from_error(error: &SandboxProviderErrorV1) -> Self {
        Self {
            attempt_id: error.attempt_id,
            public: ObservedPublic::Refused(error.code),
        }
    }
}

/// What a provider showed for one case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRun {
    /// One entry per attempt the case ran.
    pub attempts: Vec<ObservedAttempt>,
    /// Owned resources (units, mounts, namespaces, devices, directories) still
    /// present after the case; zero for a provider that cleaned up.
    pub leaked_resources: u32,
}

/// The provider could not run the case at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRunError;

/// The binding of one provider to the suite.
pub trait ProviderUnderTest {
    /// Run the case from a fresh provider state and report what it showed.
    ///
    /// # Errors
    /// Returns [`ProviderRunError`] when the case could not be run.
    fn run_case(&mut self, case: ProviderConformanceCase) -> Result<ProviderRun, ProviderRunError>;
}

/// Why a case failed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    /// The provider could not run the case.
    NotRun,
    /// The number of attempts shown is not the number the case runs.
    AttemptCount,
    /// An attempt showed a different SPY1 outcome or an SPE1 refusal where a
    /// result was required, or the reverse.
    Outcome,
    /// An attempt showed an SPY1 outcome with an unexpected terminal code.
    TerminalCode,
    /// An attempt was refused with an unexpected SPE1 code.
    Refusal,
    /// Concurrent attempts shared or omitted an attempt identity.
    AttemptIdentity,
    /// Owned resources remained after the case.
    ResourceLeak,
}

/// A case's verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "reason", rename_all = "snake_case")]
pub enum CaseVerdict {
    /// Every attempt showed the expected public outcome and left no residue.
    Passed,
    /// The case failed for this reason.
    Failed(FailureReason),
}

fn attempt_matches(
    expected: ExpectedPublicOutcome,
    observed: ObservedPublic,
) -> Result<(), FailureReason> {
    match (expected, observed) {
        (
            ExpectedPublicOutcome::Terminal { outcome, codes },
            ObservedPublic::Terminal {
                outcome: shown,
                terminal_code,
            },
        ) => {
            if outcome != shown {
                Err(FailureReason::Outcome)
            } else if terminal_code.map_or(!codes.is_empty(), |code| !codes.contains(&code)) {
                Err(FailureReason::TerminalCode)
            } else {
                Ok(())
            }
        }
        (ExpectedPublicOutcome::Refused(code), ObservedPublic::Refused(shown)) => {
            if code == shown {
                Ok(())
            } else {
                Err(FailureReason::Refusal)
            }
        }
        _ => Err(FailureReason::Outcome),
    }
}

fn identities_distinct(attempts: &[ObservedAttempt]) -> bool {
    attempts.iter().enumerate().all(|(index, attempt)| {
        attempt.attempt_id.is_some_and(|id| {
            attempts
                .iter()
                .skip(index + 1)
                .all(|other| other.attempt_id != Some(id))
        })
    })
}

/// Judge what a provider showed for a case.
#[must_use]
pub fn evaluate(case: ProviderConformanceCase, run: &ProviderRun) -> CaseVerdict {
    let attempts = case.attempts();
    let failure = if run.attempts.len() != attempts {
        Some(FailureReason::AttemptCount)
    } else if let Some(reason) = run
        .attempts
        .iter()
        .find_map(|attempt| attempt_matches(case.expectation(), attempt.public).err())
    {
        Some(reason)
    } else if attempts > 1 && !identities_distinct(&run.attempts) {
        Some(FailureReason::AttemptIdentity)
    } else if run.leaked_resources != 0 {
        Some(FailureReason::ResourceLeak)
    } else {
        None
    };
    failure.map_or(CaseVerdict::Passed, CaseVerdict::Failed)
}

/// The host architecture a report was produced on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportArchitecture {
    /// AMD64/x86-64.
    X86_64,
    /// 64-bit ARM/AArch64.
    Aarch64,
}

impl ReportArchitecture {
    /// Both architectures the gate requires.
    pub const REQUIRED: [Self; 2] = [Self::X86_64, Self::Aarch64];
}

impl From<SandboxArchitectureV1> for ReportArchitecture {
    fn from(architecture: SandboxArchitectureV1) -> Self {
        match architecture {
            SandboxArchitectureV1::X86_64 => Self::X86_64,
            SandboxArchitectureV1::Aarch64 => Self::Aarch64,
        }
    }
}

/// One case's line of a report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaseRecord {
    /// The case's report name.
    pub case: String,
    /// Its verdict.
    pub verdict: CaseVerdict,
}

/// A suite run's report for one architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SuiteReport {
    /// The architecture the run executed on.
    pub architecture: ReportArchitecture,
    /// One record per case, in [`ProviderConformanceCase::ALL`] order.
    pub cases: Vec<CaseRecord>,
}

/// Run every case against the provider.
pub fn run_suite(
    provider: &mut impl ProviderUnderTest,
    architecture: SandboxArchitectureV1,
) -> SuiteReport {
    let cases = ProviderConformanceCase::ALL
        .into_iter()
        .map(|case| CaseRecord {
            case: case.id().to_owned(),
            verdict: provider
                .run_case(case)
                .map_or(CaseVerdict::Failed(FailureReason::NotRun), |run| {
                    evaluate(case, &run)
                }),
        })
        .collect();
    SuiteReport {
        architecture: architecture.into(),
        cases,
    }
}

/// Why a set of reports does not satisfy the gate.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GateError {
    /// A required architecture has no report, or more than one.
    #[error("expected exactly one report for {0:?}")]
    ArchitectureCoverage(ReportArchitecture),
    /// A report names a case the suite does not define.
    #[error("report names an unknown case {0}")]
    UnknownCase(String),
    /// A report omits a case or repeats one.
    #[error("report does not list case {0} exactly once")]
    CaseCoverage(&'static str),
    /// A case did not pass.
    #[error("case {case} failed on {architecture:?}: {reason:?}")]
    Failed {
        /// The architecture.
        architecture: ReportArchitecture,
        /// The case's report name.
        case: &'static str,
        /// Why it failed.
        reason: FailureReason,
    },
}

fn verify_report(report: &SuiteReport) -> Result<(), GateError> {
    if let Some(record) = report
        .cases
        .iter()
        .find(|record| ProviderConformanceCase::from_id(&record.case).is_none())
    {
        return Err(GateError::UnknownCase(record.case.clone()));
    }
    for case in ProviderConformanceCase::ALL {
        let mut records = report
            .cases
            .iter()
            .filter(|record| record.case == case.id());
        let (Some(record), None) = (records.next(), records.next()) else {
            return Err(GateError::CaseCoverage(case.id()));
        };
        if let CaseVerdict::Failed(reason) = record.verdict {
            return Err(GateError::Failed {
                architecture: report.architecture,
                case: case.id(),
                reason,
            });
        }
    }
    Ok(())
}

/// Require a passing report for each required architecture and no other.
///
/// # Errors
/// Returns the first [`GateError`] found: architecture coverage first, then
/// each report in the order given.
pub fn verify_gate(reports: &[SuiteReport]) -> Result<(), GateError> {
    for architecture in ReportArchitecture::REQUIRED {
        if reports
            .iter()
            .filter(|report| report.architecture == architecture)
            .count()
            != 1
        {
            return Err(GateError::ArchitectureCoverage(architecture));
        }
    }
    reports.iter().try_for_each(verify_report)
}
