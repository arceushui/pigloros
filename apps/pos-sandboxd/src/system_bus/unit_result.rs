//! Typed terminal-result readback of the exact systemd attempt service object.

use zbus::proxy::CacheProperties;
use zbus_systemd::systemd1::ServiceProxy;

use super::{SystemdTransientUnitTransport, SystemdVerifiedStart, TransientServiceUnitName};

/// The `waitid` `si_code` values systemd reports as `ExecMainCode`.
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
/// The highest Linux signal number, including real-time signals.
const MAX_SIGNAL: u8 = 64;
/// `SIGXFSZ` on the supported Linux architectures (x86-64 and 64-bit Arm).
const SIGXFSZ: u8 = 25;

/// One closed systemd service `Result` value the provider can classify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum SystemdServiceResult {
    /// `success`.
    Success,
    /// `exit-code`.
    ExitCode,
    /// `signal`.
    Signal,
    /// `core-dump`.
    CoreDump,
    /// `timeout`, including the `RuntimeMaxSec` attempt watchdog.
    Timeout,
    /// `oom-kill`.
    OomKill,
}

const SERVICE_RESULTS: [(&str, SystemdServiceResult); 6] = [
    ("success", SystemdServiceResult::Success),
    ("exit-code", SystemdServiceResult::ExitCode),
    ("signal", SystemdServiceResult::Signal),
    ("core-dump", SystemdServiceResult::CoreDump),
    ("timeout", SystemdServiceResult::Timeout),
    ("oom-kill", SystemdServiceResult::OomKill),
];

impl SystemdServiceResult {
    fn parse(value: &str) -> Option<Self> {
        SERVICE_RESULTS
            .iter()
            .find(|(name, _)| *name == value)
            .map(|&(_, result)| result)
    }

    /// Return the exact systemd `Result` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        SERVICE_RESULTS[self as usize].0
    }
}

/// How the unit's main process ended, from `ExecMainCode` and `ExecMainStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdMainExit {
    /// `CLD_EXITED` with its exit status.
    Exited { status: u8 },
    /// `CLD_KILLED` with the terminating signal number.
    Killed { signal: u8 },
    /// `CLD_DUMPED` with the terminating signal number.
    Dumped { signal: u8 },
}

impl SystemdMainExit {
    fn decode(code: i32, status: i32) -> Result<Self, SystemdUnitResultError> {
        let decoded = match code {
            CLD_EXITED => u8::try_from(status)
                .ok()
                .map(|status| Self::Exited { status }),
            CLD_KILLED => signal_number(status).map(|signal| Self::Killed { signal }),
            CLD_DUMPED => signal_number(status).map(|signal| Self::Dumped { signal }),
            _ => return Err(SystemdUnitResultError::UnknownExecMainCode(code)),
        };
        decoded.ok_or(SystemdUnitResultError::InvalidExecMainStatus { code, status })
    }
}

fn signal_number(status: i32) -> Option<u8> {
    u8::try_from(status)
        .ok()
        .filter(|signal| (1..=MAX_SIGNAL).contains(signal))
}

/// The closed classification of one consistent service result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdUnitOutcome {
    /// `success` with main exit status zero.
    Success,
    /// `exit-code` with a nonzero main exit status.
    ExitCode { status: u8 },
    /// `signal` or `core-dump` with a signal other than `SIGXFSZ`.
    Signal { signal: u8, core_dumped: bool },
    /// `signal` or `core-dump` naming `SIGXFSZ`: the file-size ceiling.
    FileSizeLimit { core_dumped: bool },
    /// `timeout`, with the main exit systemd recorded.
    Timeout { main: SystemdMainExit },
    /// `oom-kill`, with the main exit systemd recorded.
    OomKill { main: SystemdMainExit },
}

impl SystemdUnitOutcome {
    const fn combine(result: SystemdServiceResult, main: SystemdMainExit) -> Option<Self> {
        match (result, main) {
            (SystemdServiceResult::Success, SystemdMainExit::Exited { status: 0 }) => {
                Some(Self::Success)
            }
            (SystemdServiceResult::ExitCode, SystemdMainExit::Exited { status }) if status != 0 => {
                Some(Self::ExitCode { status })
            }
            (SystemdServiceResult::Signal, SystemdMainExit::Killed { signal }) => {
                Some(Self::signaled(signal, false))
            }
            (SystemdServiceResult::CoreDump, SystemdMainExit::Dumped { signal }) => {
                Some(Self::signaled(signal, true))
            }
            (SystemdServiceResult::Timeout, main) => Some(Self::Timeout { main }),
            (SystemdServiceResult::OomKill, main) => Some(Self::OomKill { main }),
            _ => None,
        }
    }

    const fn signaled(signal: u8, core_dumped: bool) -> Self {
        if signal == SIGXFSZ {
            Self::FileSizeLimit { core_dumped }
        } else {
            Self::Signal {
                signal,
                core_dumped,
            }
        }
    }
}

/// Failure to obtain one closed, consistent service result.
#[derive(Debug, thiserror::Error)]
pub enum SystemdUnitResultError {
    /// The generated typed service proxy could not be constructed.
    #[error("failed to construct the typed systemd service proxy")]
    Proxy(#[source] zbus::Error),
    /// One typed service property could not be read or had the wrong type.
    #[error("failed to read systemd service property {property}")]
    PropertyRead {
        property: &'static str,
        #[source]
        source: Box<zbus::Error>,
    },
    /// systemd reported a `Result` outside the closed classified set.
    #[error("systemd returned unclassified service Result {0:?}")]
    UnknownResult(String),
    /// systemd reported an `ExecMainCode` that is not a terminal `si_code`.
    #[error("systemd returned unknown ExecMainCode {0}")]
    UnknownExecMainCode(i32),
    /// The `ExecMainStatus` is out of range for its `ExecMainCode`.
    #[error("ExecMainStatus {status} is invalid for ExecMainCode {code}")]
    InvalidExecMainStatus { code: i32, status: i32 },
    /// The service `Result` contradicts the recorded main exit.
    #[error("service Result {result:?} contradicts main exit {main:?}")]
    Inconsistent {
        result: SystemdServiceResult,
        main: SystemdMainExit,
    },
}

/// The terminal result read from the exact verified attempt unit object.
///
/// This classifies systemd's record only; kernel limit-event evidence and
/// outcome precedence are decided by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdUnitResultObservation {
    unit_name: TransientServiceUnitName,
    unit_path: String,
    result: SystemdServiceResult,
    main: SystemdMainExit,
    outcome: SystemdUnitOutcome,
}

impl SystemdUnitResultObservation {
    fn decode(
        started: &SystemdVerifiedStart,
        result: &str,
        code: i32,
        status: i32,
    ) -> Result<Self, SystemdUnitResultError> {
        let result = SystemdServiceResult::parse(result)
            .ok_or_else(|| SystemdUnitResultError::UnknownResult(result.to_owned()))?;
        let main = SystemdMainExit::decode(code, status)?;
        SystemdUnitOutcome::combine(result, main)
            .map(|outcome| Self {
                unit_name: started.unit_name.clone(),
                unit_path: started.unit_path.as_str().to_owned(),
                result,
                main,
                outcome,
            })
            .ok_or(SystemdUnitResultError::Inconsistent { result, main })
    }

    /// Return the exact transient service-unit name.
    #[must_use]
    pub const fn unit_name(&self) -> &TransientServiceUnitName {
        &self.unit_name
    }

    /// Return the exact unit object path the properties were read from.
    #[must_use]
    pub fn unit_path(&self) -> &str {
        &self.unit_path
    }

    /// Return the closed systemd `Result` value.
    #[must_use]
    pub const fn result(&self) -> SystemdServiceResult {
        self.result
    }

    /// Return the decoded `ExecMainCode` and `ExecMainStatus`.
    #[must_use]
    pub const fn main_exit(&self) -> SystemdMainExit {
        self.main
    }

    /// Return the consistent classification of the result.
    #[must_use]
    pub const fn outcome(&self) -> SystemdUnitOutcome {
        self.outcome
    }
}

impl SystemdTransientUnitTransport {
    /// Read `Result`, `ExecMainCode`, and `ExecMainStatus` of the started unit.
    ///
    /// The properties are read uncached from the exact object path verified
    /// at start, never from a name lookup. The caller reads them after the
    /// main exit, while the unit is still loaded.
    ///
    /// # Errors
    /// Rejects a proxy or property-read failure, a wrongly typed property, an
    /// unclassified `Result` or `ExecMainCode`, an out-of-range status, or a
    /// `Result` that contradicts the main exit.
    pub async fn read_unit_result(
        &self,
        started: &SystemdVerifiedStart,
    ) -> Result<SystemdUnitResultObservation, SystemdUnitResultError> {
        let service = ServiceProxy::builder(&self.connection)
            .path(started.unit_path.clone())
            .cache_properties(CacheProperties::No)
            .build()
            .await;
        read_with_proxy(service, started).await
    }
}

async fn read_with_proxy(
    service: zbus::Result<ServiceProxy<'_>>,
    started: &SystemdVerifiedStart,
) -> Result<SystemdUnitResultObservation, SystemdUnitResultError> {
    let service = service.map_err(SystemdUnitResultError::Proxy)?;
    let result = service.result().await.map_err(property_error("Result"))?;
    let code = service
        .exec_main_code()
        .await
        .map_err(property_error("ExecMainCode"))?;
    let status = service
        .exec_main_status()
        .await
        .map_err(property_error("ExecMainStatus"))?;
    SystemdUnitResultObservation::decode(started, &result, code, status)
}

fn property_error(property: &'static str) -> impl FnOnce(zbus::Error) -> SystemdUnitResultError {
    move |source| SystemdUnitResultError::PropertyRead {
        property,
        source: Box::new(source),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    use std::sync::atomic::{AtomicI32, Ordering};

    use zbus::{fdo, Connection, OwnedObjectPath};

    use crate::system_bus::test_support::peer_connections;
    use crate::system_bus::SystemdStartJob;
    use crate::{SystemdManagerReadback, SystemdManagerReadbackOnlyProperty};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const UNIT_PATH: &str =
        "/org/freedesktop/systemd1/unit/pigloros_2dattempt_2d40404040404040404040404040404040_2eservice";

    struct ResultService {
        result: String,
        code: i32,
        status: i32,
        failing: Option<&'static str>,
    }

    impl ResultService {
        fn read<T>(&self, property: &str, value: T) -> fdo::Result<T> {
            if self.failing == Some(property) {
                Err(fdo::Error::Failed(format!("test {property} read failure")))
            } else {
                Ok(value)
            }
        }
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl ResultService {
        #[zbus(property, name = "Result")]
        fn result(&self) -> fdo::Result<String> {
            self.read("Result", self.result.clone())
        }

        #[zbus(property, name = "ExecMainCode")]
        fn exec_main_code(&self) -> fdo::Result<i32> {
            self.read("ExecMainCode", self.code)
        }

        #[zbus(property, name = "ExecMainStatus")]
        fn exec_main_status(&self) -> fdo::Result<i32> {
            self.read("ExecMainStatus", self.status)
        }
    }

    /// Serves `Result` as `ay` instead of `s`.
    struct WrongResultType(Vec<u8>);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongResultType {
        #[zbus(property, name = "Result")]
        fn result(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    /// Serves `ExecMainCode` as `s` instead of `i`.
    struct WrongCodeType(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongCodeType {
        #[zbus(property, name = "Result")]
        fn result(&self) -> String {
            self.0.clone()
        }

        #[zbus(property, name = "ExecMainCode")]
        fn exec_main_code(&self) -> String {
            self.0.clone()
        }
    }

    /// Serves `ExecMainStatus` as `s` instead of `i`.
    struct WrongStatusType(String, AtomicI32);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongStatusType {
        #[zbus(property, name = "Result")]
        fn result(&self) -> String {
            self.0.clone()
        }

        #[zbus(property, name = "ExecMainCode")]
        fn exec_main_code(&self) -> i32 {
            self.1.load(Ordering::SeqCst)
        }

        #[zbus(property, name = "ExecMainStatus")]
        fn exec_main_status(&self) -> String {
            self.0.clone()
        }
    }

    fn started() -> TestResult<SystemdVerifiedStart> {
        Ok(SystemdVerifiedStart {
            unit_name: TransientServiceUnitName::from_attempt_id([0x40; 16])?,
            job: SystemdStartJob(OwnedObjectPath::try_from(
                "/org/freedesktop/systemd1/job/7",
            )?),
            unit_path: OwnedObjectPath::try_from(UNIT_PATH)?,
            requested_readback: Vec::new(),
            manager_readback: SystemdManagerReadback::new(
                SystemdManagerReadbackOnlyProperty::RootImagePolicy,
                "",
            ),
        })
    }

    async fn serve<I: zbus::object_server::Interface>(
        service: I,
    ) -> TestResult<(SystemdTransientUnitTransport, Connection)> {
        let (server, client) =
            peer_connections(|server| server.serve_at(UNIT_PATH, service)).await?;
        Ok((SystemdTransientUnitTransport { connection: client }, server))
    }

    async fn read(
        result: &str,
        code: i32,
        status: i32,
    ) -> TestResult<Result<SystemdUnitResultObservation, SystemdUnitResultError>> {
        let service = ResultService {
            result: result.to_owned(),
            code,
            status,
            failing: None,
        };
        let (transport, _server) = serve(service).await?;
        Ok(transport.read_unit_result(&started()?).await)
    }

    const fn signaled(signal: u8, core_dumped: bool) -> SystemdUnitOutcome {
        SystemdUnitOutcome::Signal {
            signal,
            core_dumped,
        }
    }

    const fn file_size(core_dumped: bool) -> SystemdUnitOutcome {
        SystemdUnitOutcome::FileSizeLimit { core_dumped }
    }

    #[tokio::test]
    async fn every_consistent_result_and_main_exit_is_classified() -> TestResult {
        let killed = SystemdMainExit::Killed { signal: 9 };
        let exited = SystemdMainExit::Exited { status: 0 };
        let dumped = SystemdMainExit::Dumped { signal: 6 };
        let timeout = |main| SystemdUnitOutcome::Timeout { main };
        let oom = |main| SystemdUnitOutcome::OomKill { main };
        let exit_code = |status| SystemdUnitOutcome::ExitCode { status };
        let cases = [
            ("success", CLD_EXITED, 0, SystemdUnitOutcome::Success),
            ("exit-code", CLD_EXITED, 1, exit_code(1)),
            ("exit-code", CLD_EXITED, 255, exit_code(255)),
            ("signal", CLD_KILLED, 1, signaled(1, false)),
            ("signal", CLD_KILLED, 9, signaled(9, false)),
            ("signal", CLD_KILLED, 24, signaled(24, false)),
            ("signal", CLD_KILLED, 25, file_size(false)),
            ("signal", CLD_KILLED, 26, signaled(26, false)),
            ("signal", CLD_KILLED, 64, signaled(64, false)),
            ("core-dump", CLD_DUMPED, 6, signaled(6, true)),
            ("core-dump", CLD_DUMPED, 25, file_size(true)),
            ("timeout", CLD_KILLED, 9, timeout(killed)),
            ("timeout", CLD_EXITED, 0, timeout(exited)),
            ("timeout", CLD_DUMPED, 6, timeout(dumped)),
            ("oom-kill", CLD_KILLED, 9, oom(killed)),
            ("oom-kill", CLD_EXITED, 0, oom(exited)),
            ("oom-kill", CLD_DUMPED, 6, oom(dumped)),
        ];
        for (result, code, status, outcome) in cases {
            let observed = read(result, code, status).await??;
            assert_eq!(observed.outcome(), outcome, "{result} {code} {status}");
            assert_eq!(observed.result().as_str(), result);
            assert_eq!(
                observed.unit_name(),
                &TransientServiceUnitName::from_attempt_id([0x40; 16])?
            );
            assert_eq!(observed.unit_path(), UNIT_PATH);
            let main = observed.main_exit();
            let expected_main = match code {
                CLD_EXITED => SystemdMainExit::Exited {
                    status: u8::try_from(status)?,
                },
                CLD_KILLED => SystemdMainExit::Killed {
                    signal: u8::try_from(status)?,
                },
                _ => SystemdMainExit::Dumped {
                    signal: u8::try_from(status)?,
                },
            };
            assert_eq!(main, expected_main);
        }
        Ok(())
    }

    #[tokio::test]
    async fn every_contradictory_result_and_main_exit_is_refused() -> TestResult {
        let cases = [
            ("success", CLD_EXITED, 1),
            ("success", CLD_KILLED, 9),
            ("success", CLD_DUMPED, 6),
            ("exit-code", CLD_EXITED, 0),
            ("exit-code", CLD_KILLED, 9),
            ("exit-code", CLD_DUMPED, 6),
            ("signal", CLD_EXITED, 0),
            ("signal", CLD_EXITED, 25),
            ("signal", CLD_DUMPED, 6),
            ("core-dump", CLD_EXITED, 0),
            ("core-dump", CLD_KILLED, 9),
        ];
        for (result, code, status) in cases {
            let observed = read(result, code, status).await?;
            assert!(
                matches!(
                    observed,
                    Err(SystemdUnitResultError::Inconsistent { result: parsed, .. })
                        if parsed.as_str() == result
                ),
                "{result} {code} {status}: {observed:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn unknown_results_codes_and_statuses_are_typed_errors() -> TestResult {
        for result in [
            "",
            "resources",
            "watchdog",
            "protocol",
            "start-limit-hit",
            "Success",
        ] {
            assert!(matches!(
                read(result, CLD_EXITED, 0).await?,
                Err(SystemdUnitResultError::UnknownResult(value)) if value == result
            ));
        }
        for code in [0, 4, 5, 6, -1, i32::MAX] {
            assert!(matches!(
                read("success", code, 0).await?,
                Err(SystemdUnitResultError::UnknownExecMainCode(value)) if value == code
            ));
        }
        for (code, status) in [
            (CLD_EXITED, -1),
            (CLD_EXITED, 256),
            (CLD_KILLED, 0),
            (CLD_KILLED, 65),
            (CLD_KILLED, -9),
            (CLD_DUMPED, 0),
            (CLD_DUMPED, 65),
        ] {
            assert!(matches!(
                read("timeout", code, status).await?,
                Err(SystemdUnitResultError::InvalidExecMainStatus { code: c, status: s })
                    if c == code && s == status
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn property_read_failures_and_wrong_types_are_typed_errors() -> TestResult {
        for property in ["Result", "ExecMainCode", "ExecMainStatus"] {
            let service = ResultService {
                result: "success".to_owned(),
                code: CLD_EXITED,
                status: 0,
                failing: Some(property),
            };
            let (transport, _server) = serve(service).await?;
            assert!(matches!(
                transport.read_unit_result(&started()?).await,
                Err(SystemdUnitResultError::PropertyRead { property: read, .. }) if read == property
            ));
        }
        let (transport, _server) = serve(WrongResultType(b"success".to_vec())).await?;
        assert!(matches!(
            transport.read_unit_result(&started()?).await,
            Err(SystemdUnitResultError::PropertyRead {
                property: "Result",
                ..
            })
        ));
        let (transport, _server) = serve(WrongCodeType("success".to_owned())).await?;
        assert!(matches!(
            transport.read_unit_result(&started()?).await,
            Err(SystemdUnitResultError::PropertyRead {
                property: "ExecMainCode",
                ..
            })
        ));
        let (transport, _server) = serve(WrongStatusType(
            "success".to_owned(),
            AtomicI32::new(CLD_EXITED),
        ))
        .await?;
        assert!(matches!(
            transport.read_unit_result(&started()?).await,
            Err(SystemdUnitResultError::PropertyRead {
                property: "ExecMainStatus",
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn another_unit_object_is_never_read() -> TestResult {
        let service = ResultService {
            result: "success".to_owned(),
            code: CLD_EXITED,
            status: 0,
            failing: None,
        };
        let (transport, _server) = serve(service).await?;
        let mut other = started()?;
        other.unit_path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/other")?;
        assert!(matches!(
            transport.read_unit_result(&other).await,
            Err(SystemdUnitResultError::PropertyRead {
                property: "Result",
                ..
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_proxy_construction_failure_is_classified() -> TestResult {
        let failed = Err(zbus::Error::InvalidField);
        assert!(matches!(
            read_with_proxy(failed, &started()?).await,
            Err(SystemdUnitResultError::Proxy(zbus::Error::InvalidField))
        ));
        Ok(())
    }
}
