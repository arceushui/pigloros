//! Typed terminal-result readback of the exact systemd attempt service object.

use std::collections::HashMap;

use rustix::process::Signal;
use zbus::{fdo::PropertiesProxy, names::InterfaceName, OwnedVariant};

use super::{SystemdTransientUnitTransport, SystemdVerifiedStart, TransientServiceUnitName};

const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
/// The `ActiveState` values in which systemd has finished with a unit run.
const SETTLED_STATES: [&str; 2] = ["inactive", "failed"];

/// `ExecMainCode` when systemd recorded no main exit, and the `waitid`
/// `si_code` values it reports for a recorded one.
const CLD_NONE: i32 = 0;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
/// The highest Linux signal number, including real-time signals.
const MAX_SIGNAL: u8 = 64;
/// The signals systemd v260.2's `is_clean_exit` treats as a clean main exit
/// of a non-oneshot service (`EXIT_CLEAN_DAEMON`), such as this `Type=exec`
/// attempt unit, when no `SuccessExitStatus=` is set.
const DAEMON_CLEAN_SIGNALS: [Signal; 4] = [Signal::HUP, Signal::INT, Signal::PIPE, Signal::TERM];

/// One systemd service `Result` value, total over systemd v260.2's
/// `service_result_table` and in its numeric order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum SystemdServiceResult {
    /// `success`.
    Success,
    /// `resources`: systemd's catch-all for an unexpected setup error.
    Resources,
    /// `protocol`.
    Protocol,
    /// `timeout`, including the `RuntimeMaxSec` attempt watchdog.
    Timeout,
    /// `exit-code`.
    ExitCode,
    /// `signal`.
    Signal,
    /// `core-dump`.
    CoreDump,
    /// `watchdog`.
    Watchdog,
    /// `start-limit-hit`.
    StartLimitHit,
    /// `oom-kill`, by the kernel or systemd-oomd.
    OomKill,
    /// `exec-condition`: an `ExecCondition=` command skipped the unit.
    ExecCondition,
}

const SERVICE_RESULTS: [(&str, SystemdServiceResult); 11] = [
    ("success", SystemdServiceResult::Success),
    ("resources", SystemdServiceResult::Resources),
    ("protocol", SystemdServiceResult::Protocol),
    ("timeout", SystemdServiceResult::Timeout),
    ("exit-code", SystemdServiceResult::ExitCode),
    ("signal", SystemdServiceResult::Signal),
    ("core-dump", SystemdServiceResult::CoreDump),
    ("watchdog", SystemdServiceResult::Watchdog),
    ("start-limit-hit", SystemdServiceResult::StartLimitHit),
    ("oom-kill", SystemdServiceResult::OomKill),
    ("exec-condition", SystemdServiceResult::ExecCondition),
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
    /// Code and status zero: systemd recorded no main exit.
    NotRecorded,
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
            CLD_NONE => (status == 0).then_some(Self::NotRecorded),
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

/// The classification of one consistent service result.
///
/// Every systemd `Result` has a variant. The ones that describe the main
/// exit themselves (`success`, `exit-code`, `signal`, `core-dump`) must agree
/// with it, using systemd's own clean-exit rule. All others carry the main
/// exit systemd recorded, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemdUnitOutcome {
    /// `success` with main exit status zero.
    Success,
    /// `success` after `SIGHUP`, `SIGINT`, `SIGPIPE` or `SIGTERM`, which
    /// systemd counts as a clean exit for a non-oneshot service.
    ///
    /// A `SIGTERM` here cannot be told apart from a stop the daemon itself
    /// requested, such as a cancel or a shutdown. Callers must not read it as
    /// the payload ending on its own, and must apply their own cancel
    /// precedence first (R9: a revocation cancel yields SPY1 `Cancelled`).
    CleanSignal { signal: u8 },
    /// `exit-code` with a nonzero main exit status.
    ExitCode { status: u8 },
    /// `signal` or `core-dump` with a signal other than `SIGXFSZ`.
    Signal { signal: u8, core_dumped: bool },
    /// `signal` or `core-dump` naming `SIGXFSZ`.
    ///
    /// This is only a hint that the file-size ceiling was reached: a payload
    /// can raise `SIGXFSZ` itself. Classifying it as the ceiling needs kernel
    /// or `/work` evidence.
    FileSizeLimit { core_dumped: bool },
    /// `timeout`.
    Timeout { main: SystemdMainExit },
    /// `oom-kill`.
    OomKill { main: SystemdMainExit },
    /// `resources`.
    Resources { main: SystemdMainExit },
    /// `protocol`.
    Protocol { main: SystemdMainExit },
    /// `watchdog`.
    Watchdog { main: SystemdMainExit },
    /// `start-limit-hit`.
    StartLimitHit { main: SystemdMainExit },
    /// `exec-condition`.
    ExecCondition { main: SystemdMainExit },
}

impl SystemdUnitOutcome {
    fn combine(result: SystemdServiceResult, main: SystemdMainExit) -> Option<Self> {
        match (result, main) {
            (SystemdServiceResult::Success, SystemdMainExit::Exited { status: 0 }) => {
                Some(Self::Success)
            }
            (SystemdServiceResult::Success, SystemdMainExit::Killed { signal })
                if is_daemon_clean_signal(signal) =>
            {
                Some(Self::CleanSignal { signal })
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
            (SystemdServiceResult::Resources, main) => Some(Self::Resources { main }),
            (SystemdServiceResult::Protocol, main) => Some(Self::Protocol { main }),
            (SystemdServiceResult::Watchdog, main) => Some(Self::Watchdog { main }),
            (SystemdServiceResult::StartLimitHit, main) => Some(Self::StartLimitHit { main }),
            (SystemdServiceResult::ExecCondition, main) => Some(Self::ExecCondition { main }),
            _ => None,
        }
    }

    fn signaled(signal: u8, core_dumped: bool) -> Self {
        if i32::from(signal) == Signal::XFSZ.as_raw() {
            Self::FileSizeLimit { core_dumped }
        } else {
            Self::Signal {
                signal,
                core_dumped,
            }
        }
    }
}

fn is_daemon_clean_signal(signal: u8) -> bool {
    DAEMON_CLEAN_SIGNALS
        .iter()
        .any(|clean| clean.as_raw() == i32::from(signal))
}

/// Failure to obtain one closed, consistent service result.
#[derive(Debug, thiserror::Error)]
pub enum SystemdUnitResultError {
    /// The typed properties proxy could not be constructed.
    #[error("failed to construct the systemd unit properties proxy")]
    Proxy(#[source] zbus::Error),
    /// One property snapshot could not be read, or one property in it was
    /// missing or had the wrong type.
    #[error("failed to read systemd unit property {property}")]
    PropertyRead {
        property: &'static str,
        #[source]
        source: Box<zbus::Error>,
    },
    /// The unit had not settled, so its result could still change.
    ///
    /// Each `InvocationID` is validated as its snapshot is read, before this
    /// check, so a malformed ID is reported as `InvocationIdMalformed` even
    /// for an unsettled unit. `NotSettled` therefore does not imply that the
    /// ID was well formed or matched.
    #[error("systemd unit is {active_state:?}, not inactive or failed")]
    NotSettled { active_state: String },
    /// `ActiveState` or `InvocationID` changed while the result was read.
    #[error("systemd unit state changed while its result was read")]
    StateChanged,
    /// The unit's `InvocationID` is not exactly 16 bytes, or is all zero.
    ///
    /// This takes precedence over `NotSettled`, `StateChanged` and
    /// `InvocationMismatch`.
    #[error("systemd returned a malformed InvocationID")]
    InvocationIdMalformed,
    /// The unit is running a different invocation than the attempt started.
    #[error("systemd unit InvocationID differs from the attempt's invocation")]
    InvocationMismatch,
    /// systemd reported a `Result` outside its `service_result_table`.
    #[error("systemd returned unknown service Result {0:?}")]
    UnknownResult(String),
    /// systemd reported an `ExecMainCode` that is neither zero nor a terminal `si_code`.
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

/// The settled `ActiveState` and `InvocationID` around one result snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
struct UnitState {
    active_state: String,
    invocation_id: [u8; 16],
}

impl UnitState {
    /// Check, in order: a settled `ActiveState`, an identical state in both
    /// snapshots, and the attempt's `InvocationID`.
    ///
    /// `InvocationMismatch` is reported only when both snapshots carry the
    /// same ID; an ID that changes between them is `StateChanged`.
    fn settled(
        self,
        after: &Self,
        invocation_id: [u8; 16],
    ) -> Result<Self, SystemdUnitResultError> {
        if !SETTLED_STATES.contains(&self.active_state.as_str()) {
            return Err(SystemdUnitResultError::NotSettled {
                active_state: self.active_state,
            });
        }
        if self != *after {
            return Err(SystemdUnitResultError::StateChanged);
        }
        if self.invocation_id != invocation_id {
            return Err(SystemdUnitResultError::InvocationMismatch);
        }
        Ok(self)
    }
}

/// One exactly 16-byte, nonzero systemd `InvocationID`.
fn invocation_id(raw: &[u8]) -> Result<[u8; 16], SystemdUnitResultError> {
    <[u8; 16]>::try_from(raw)
        .ok()
        .filter(|id| *id != [0; 16])
        .ok_or(SystemdUnitResultError::InvocationIdMalformed)
}

/// The terminal result read from the exact verified attempt unit object.
///
/// This classifies systemd's record only; kernel limit-event evidence and
/// outcome precedence are decided by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdUnitResultObservation {
    unit_name: TransientServiceUnitName,
    unit_path: String,
    state: UnitState,
    result: SystemdServiceResult,
    main: SystemdMainExit,
    outcome: SystemdUnitOutcome,
}

impl SystemdUnitResultObservation {
    fn decode(
        started: &SystemdVerifiedStart,
        state: UnitState,
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
                state,
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

    /// Return the settled `ActiveState`: `inactive` or `failed`.
    #[must_use]
    pub fn active_state(&self) -> &str {
        &self.state.active_state
    }

    /// Return the attempt's `InvocationID`, unchanged across the snapshot.
    #[must_use]
    pub const fn invocation_id(&self) -> [u8; 16] {
        self.state.invocation_id
    }

    /// Return the systemd `Result` value.
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

type PropertySnapshot = HashMap<String, OwnedVariant>;

impl SystemdTransientUnitTransport {
    /// Read the settled result of the started unit as one snapshot.
    ///
    /// One `GetAll` of the `Service` interface returns `Result`,
    /// `ExecMainCode` and `ExecMainStatus` together. A `GetAll` of the `Unit`
    /// interface before and after must report the same settled
    /// `ActiveState` (`inactive` or `failed`) and `InvocationID`, and that
    /// `InvocationID` must equal `invocation_id`, the attempt's invocation
    /// captured at start. A reused unit path therefore cannot substitute a
    /// later run, or a unit that never ran. Every read targets the exact
    /// object path verified at start, never a name lookup, and nothing is
    /// cached. The caller reads after the main exit, while the unit is still
    /// loaded.
    ///
    /// Like the rest of this transport, the proxy addresses the well-known
    /// name `org.freedesktop.systemd1`. It assumes the transport's bus
    /// connection only lets the real manager own that name; this method does
    /// not pin the owner's unique name.
    ///
    /// # Errors
    /// Rejects a proxy or snapshot failure, a missing or wrongly typed
    /// property, an unsettled or changing unit, a malformed or different
    /// `InvocationID`, an unknown `Result` or `ExecMainCode`, an out-of-range
    /// status, or a `Result` that contradicts the main exit.
    ///
    /// A malformed `InvocationID` is detected while each snapshot is read, so
    /// it wins over `NotSettled`: an unsettled unit with a zero ID reports
    /// `InvocationIdMalformed`, and `NotSettled` does not imply a valid ID.
    /// `InvocationMismatch` needs the same ID in both snapshots; an ID that
    /// changes between them is `StateChanged`.
    pub async fn read_unit_result(
        &self,
        started: &SystemdVerifiedStart,
        invocation_id: [u8; 16],
    ) -> Result<SystemdUnitResultObservation, SystemdUnitResultError> {
        let properties = PropertiesProxy::builder(&self.connection)
            .destination(SYSTEMD_DESTINATION)
            .path(started.unit_path.clone())
            .build()
            .await;
        read_with_proxy(properties, started, invocation_id).await
    }
}

async fn read_with_proxy(
    properties: zbus::Result<PropertiesProxy<'_>>,
    started: &SystemdVerifiedStart,
    invocation_id: [u8; 16],
) -> Result<SystemdUnitResultObservation, SystemdUnitResultError> {
    let properties = properties.map_err(SystemdUnitResultError::Proxy)?;
    let before = read_unit_state(&properties).await?;
    let mut service = snapshot(&properties, SERVICE_INTERFACE).await?;
    let after = read_unit_state(&properties).await?;
    let state = before.settled(&after, invocation_id)?;
    let result: String = take(&mut service, "Result")?;
    let code = take(&mut service, "ExecMainCode")?;
    let status = take(&mut service, "ExecMainStatus")?;
    SystemdUnitResultObservation::decode(started, state, &result, code, status)
}

async fn read_unit_state(
    properties: &PropertiesProxy<'_>,
) -> Result<UnitState, SystemdUnitResultError> {
    let mut unit = snapshot(properties, UNIT_INTERFACE).await?;
    let active_state = take(&mut unit, "ActiveState")?;
    let raw: Vec<u8> = take(&mut unit, "InvocationID")?;
    Ok(UnitState {
        active_state,
        invocation_id: invocation_id(&raw)?,
    })
}

async fn snapshot(
    properties: &PropertiesProxy<'_>,
    interface: &'static str,
) -> Result<PropertySnapshot, SystemdUnitResultError> {
    properties
        .get_all(InterfaceName::from_static_str_unchecked(interface))
        .await
        .map_err(|error| property_error(interface)(error.into()))
}

fn take<T>(
    snapshot: &mut PropertySnapshot,
    property: &'static str,
) -> Result<T, SystemdUnitResultError>
where
    T: TryFrom<OwnedVariant, Error = zbus::Error>,
{
    snapshot
        .remove(property)
        .ok_or(zbus::Error::MissingField)
        .and_then(T::try_from)
        .map_err(property_error(property))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zbus::{fdo, object_server::Interface, OwnedObjectPath};

    use crate::system_bus::test_support::peer_connections;
    use crate::system_bus::SystemdStartJob;
    use crate::{SystemdManagerReadback, SystemdManagerReadbackOnlyProperty};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
    type Read = Result<SystemdUnitResultObservation, SystemdUnitResultError>;
    /// Builds the outcome of a `Result` that carries the recorded main exit.
    type Recorded = fn(SystemdMainExit) -> SystemdUnitOutcome;

    const UNIT_PATH: &str =
        "/org/freedesktop/systemd1/unit/pigloros_2dattempt_2d40404040404040404040404040404040_2eservice";
    const INVOCATION: [u8; 16] = [0x11; 16];

    fn failed() -> Vec<(String, Vec<u8>)> {
        vec![("failed".to_owned(), INVOCATION.to_vec())]
    }

    /// Serves `ActiveState` and `InvocationID`; the n-th `GetAll` sees the
    /// n-th state, and the last state repeats.
    struct UnitFixture {
        states: Vec<(String, Vec<u8>)>,
        state_reads: AtomicUsize,
        invocation_reads: AtomicUsize,
        failing: Option<&'static str>,
    }

    impl UnitFixture {
        fn new(states: Vec<(String, Vec<u8>)>) -> Self {
            Self {
                states,
                state_reads: AtomicUsize::new(0),
                invocation_reads: AtomicUsize::new(0),
                failing: None,
            }
        }

        fn state(&self, reads: &AtomicUsize) -> &(String, Vec<u8>) {
            let read = reads.fetch_add(1, Ordering::SeqCst);
            &self.states[read.min(self.states.len() - 1)]
        }

        fn check(&self, property: &str) -> fdo::Result<()> {
            if self.failing == Some(property) {
                Err(fdo::Error::Failed(format!("test {property} read failure")))
            } else {
                Ok(())
            }
        }
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl UnitFixture {
        #[zbus(property, name = "ActiveState")]
        fn active_state(&self) -> fdo::Result<String> {
            self.check("ActiveState")
                .map(|()| self.state(&self.state_reads).0.clone())
        }

        #[zbus(property, name = "InvocationID")]
        fn invocation_id(&self) -> fdo::Result<Vec<u8>> {
            self.check("InvocationID")
                .map(|()| self.state(&self.invocation_reads).1.clone())
        }
    }

    struct ServiceFixture {
        result: String,
        code: i32,
        status: i32,
        failing: Option<&'static str>,
    }

    impl ServiceFixture {
        fn new(result: &str, code: i32, status: i32) -> Self {
            Self {
                result: result.to_owned(),
                code,
                status,
                failing: None,
            }
        }

        fn read<T>(&self, property: &str, value: T) -> fdo::Result<T> {
            if self.failing == Some(property) {
                Err(fdo::Error::Failed(format!("test {property} read failure")))
            } else {
                Ok(value)
            }
        }
    }

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl ServiceFixture {
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

    /// Serves `Result` typed `ay`.
    struct WrongService(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongService {
        #[zbus(property, name = "Result")]
        fn result(&self) -> Vec<u8> {
            self.0.clone().into_bytes()
        }
    }

    /// Serves a correct `Result` and a `ExecMainCode` typed `s`.
    struct WrongCodeService(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongCodeService {
        #[zbus(property, name = "Result")]
        fn result(&self) -> String {
            self.0.clone()
        }

        #[zbus(property, name = "ExecMainCode")]
        fn exec_main_code(&self) -> String {
            self.0.clone()
        }
    }

    /// Serves `ExecMainStatus` typed `s` next to correct values.
    struct WrongStatusService(ServiceFixture);

    #[zbus::interface(name = "org.freedesktop.systemd1.Service")]
    impl WrongStatusService {
        #[zbus(property, name = "Result")]
        fn result(&self) -> String {
            self.0.result.clone()
        }

        #[zbus(property, name = "ExecMainCode")]
        fn exec_main_code(&self) -> fdo::Result<i32> {
            self.0.read("ExecMainCode", self.0.code)
        }

        #[zbus(property, name = "ExecMainStatus")]
        fn exec_main_status(&self) -> String {
            self.0.result.clone()
        }
    }

    /// Serves `ActiveState` typed `ay`.
    struct WrongStateUnit(Vec<u8>);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl WrongStateUnit {
        #[zbus(property, name = "ActiveState")]
        fn active_state(&self) -> Vec<u8> {
            self.0.clone()
        }

        #[zbus(property, name = "InvocationID")]
        fn invocation_id(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    /// Serves `InvocationID` typed `s`.
    struct WrongInvocationUnit(String);

    #[zbus::interface(name = "org.freedesktop.systemd1.Unit")]
    impl WrongInvocationUnit {
        #[zbus(property, name = "ActiveState")]
        fn active_state(&self) -> String {
            self.0.clone()
        }

        #[zbus(property, name = "InvocationID")]
        fn invocation_id(&self) -> String {
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

    async fn read_from(unit: impl Interface, service: Option<impl Interface>) -> TestResult<Read> {
        let (_server, client) = peer_connections(|server| {
            service
                .into_iter()
                .fold(server.serve_at(UNIT_PATH, unit), |server, service| {
                    server.serve_at(UNIT_PATH, service)
                })
        })
        .await?;
        let transport = SystemdTransientUnitTransport { connection: client };
        let started = started()?;
        let observed = transport.read_unit_result(&started, INVOCATION).await;
        Ok(observed)
    }

    async fn read(result: &str, code: i32, status: i32) -> TestResult<Read> {
        read_from(
            UnitFixture::new(failed()),
            Some(ServiceFixture::new(result, code, status)),
        )
        .await
    }

    fn assert_property(read: &Read, expected: &str) {
        assert!(
            matches!(read, Err(SystemdUnitResultError::PropertyRead { property, .. }) if *property == expected),
            "{expected}: {read:?}"
        );
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

    const fn main_of(code: i32, status: u8) -> SystemdMainExit {
        match code {
            CLD_NONE => SystemdMainExit::NotRecorded,
            CLD_EXITED => SystemdMainExit::Exited { status },
            CLD_KILLED => SystemdMainExit::Killed { signal: status },
            _ => SystemdMainExit::Dumped { signal: status },
        }
    }

    #[test]
    fn every_service_result_round_trips_in_systemd_table_order() {
        assert_eq!(SERVICE_RESULTS.len(), 11);
        for (index, (name, result)) in SERVICE_RESULTS.into_iter().enumerate() {
            assert_eq!(result as usize, index);
            assert_eq!(result.as_str(), name);
            assert_eq!(SystemdServiceResult::parse(result.as_str()), Some(result));
        }
        let names = SERVICE_RESULTS.map(|(name, _)| name);
        assert_eq!(
            names,
            [
                "success",
                "resources",
                "protocol",
                "timeout",
                "exit-code",
                "signal",
                "core-dump",
                "watchdog",
                "start-limit-hit",
                "oom-kill",
                "exec-condition",
            ]
        );
    }

    #[tokio::test]
    async fn every_consistent_result_and_main_exit_is_classified() -> TestResult {
        let exit_code = |status| SystemdUnitOutcome::ExitCode { status };
        let clean = |signal| SystemdUnitOutcome::CleanSignal { signal };
        let mut cases = vec![
            ("success", CLD_EXITED, 0, SystemdUnitOutcome::Success),
            ("success", CLD_KILLED, 1, clean(1)),
            ("success", CLD_KILLED, 2, clean(2)),
            ("success", CLD_KILLED, 13, clean(13)),
            ("success", CLD_KILLED, 15, clean(15)),
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
        ];
        let recorded: [(&str, Recorded); 7] = [
            ("timeout", |main| SystemdUnitOutcome::Timeout { main }),
            ("oom-kill", |main| SystemdUnitOutcome::OomKill { main }),
            ("resources", |main| SystemdUnitOutcome::Resources { main }),
            ("protocol", |main| SystemdUnitOutcome::Protocol { main }),
            ("watchdog", |main| SystemdUnitOutcome::Watchdog { main }),
            ("start-limit-hit", |main| {
                SystemdUnitOutcome::StartLimitHit { main }
            }),
            ("exec-condition", |main| SystemdUnitOutcome::ExecCondition {
                main,
            }),
        ];
        for (result, outcome) in recorded {
            for (code, status) in [
                (CLD_NONE, 0),
                (CLD_EXITED, 0),
                (CLD_EXITED, 3),
                (CLD_KILLED, 9),
                (CLD_DUMPED, 6),
            ] {
                cases.push((
                    result,
                    code,
                    i32::from(status),
                    outcome(main_of(code, status)),
                ));
            }
        }
        for (result, code, status, outcome) in cases {
            let observed = read(result, code, status).await??;
            assert_eq!(observed.outcome(), outcome, "{result} {code} {status}");
            assert_eq!(observed.result().as_str(), result);
            assert_eq!(observed.main_exit(), main_of(code, u8::try_from(status)?));
            assert_eq!(
                observed.unit_name(),
                &TransientServiceUnitName::from_attempt_id([0x40; 16])?
            );
            assert_eq!(observed.unit_path(), UNIT_PATH);
            assert_eq!(observed.active_state(), "failed");
            assert_eq!(observed.invocation_id(), INVOCATION);
        }
        Ok(())
    }

    #[tokio::test]
    async fn every_contradictory_result_and_main_exit_is_refused() -> TestResult {
        let cases = [
            ("success", CLD_NONE, 0),
            ("success", CLD_EXITED, 1),
            ("success", CLD_KILLED, 3),
            ("success", CLD_KILLED, 9),
            ("success", CLD_KILLED, 14),
            ("success", CLD_KILLED, 16),
            ("success", CLD_KILLED, 25),
            ("success", CLD_DUMPED, 15),
            ("success", CLD_DUMPED, 6),
            ("exit-code", CLD_NONE, 0),
            ("exit-code", CLD_EXITED, 0),
            ("exit-code", CLD_KILLED, 9),
            ("exit-code", CLD_DUMPED, 6),
            ("signal", CLD_NONE, 0),
            ("signal", CLD_EXITED, 0),
            ("signal", CLD_EXITED, 25),
            ("signal", CLD_DUMPED, 6),
            ("core-dump", CLD_NONE, 0),
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
            "Success",
            "skip-condition",
            "oom",
            "exec_condition",
            "success ",
        ] {
            assert!(matches!(
                read(result, CLD_EXITED, 0).await?,
                Err(SystemdUnitResultError::UnknownResult(value)) if value == result
            ));
        }
        for code in [4, 5, 6, -1, i32::MAX] {
            assert!(matches!(
                read("success", code, 0).await?,
                Err(SystemdUnitResultError::UnknownExecMainCode(value)) if value == code
            ));
        }
        for (code, status) in [
            (CLD_NONE, 1),
            (CLD_NONE, -1),
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
    async fn an_unsettled_unit_is_refused() -> TestResult {
        for state in [
            "active",
            "activating",
            "deactivating",
            "reloading",
            "maintenance",
            "",
        ] {
            let unit = UnitFixture::new(vec![(state.to_owned(), INVOCATION.to_vec())]);
            let observed =
                read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
            assert!(
                matches!(
                    &observed,
                    Err(SystemdUnitResultError::NotSettled { active_state }) if active_state == state
                ),
                "{state}: {observed:?}"
            );
        }
        let unit = UnitFixture::new(vec![("inactive".to_owned(), INVOCATION.to_vec())]);
        let observed =
            read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await??;
        assert_eq!(observed.active_state(), "inactive");
        assert_eq!(observed.invocation_id(), INVOCATION);
        Ok(())
    }

    #[tokio::test]
    async fn a_malformed_invocation_id_wins_over_an_unsettled_state() -> TestResult {
        for (state, raw) in [("activating", vec![0; 16]), ("active", Vec::new())] {
            let unit = UnitFixture::new(vec![(state.to_owned(), raw)]);
            let observed =
                read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
            assert!(
                matches!(observed, Err(SystemdUnitResultError::InvocationIdMalformed)),
                "{state}: {observed:?}"
            );
        }
        let unit = UnitFixture::new(vec![
            ("failed".to_owned(), vec![0x33; 16]),
            ("failed".to_owned(), vec![0x22; 16]),
        ]);
        let observed = read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
        assert!(
            matches!(observed, Err(SystemdUnitResultError::StateChanged)),
            "{observed:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_result_is_bound_to_the_attempts_exact_invocation() -> TestResult {
        let malformed = [
            Vec::new(),
            vec![0; 16],
            vec![0x11; 15],
            vec![0x11; 17],
            vec![0x11; 32],
        ];
        let mut one_bit = [0; 16];
        one_bit[15] = 1;
        assert_eq!(invocation_id(&one_bit)?, one_bit);
        for raw in malformed {
            for states in [
                vec![("failed".to_owned(), raw.clone())],
                vec![
                    ("failed".to_owned(), INVOCATION.to_vec()),
                    ("failed".to_owned(), raw.clone()),
                ],
            ] {
                let unit = UnitFixture::new(states);
                let observed =
                    read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
                assert!(
                    matches!(observed, Err(SystemdUnitResultError::InvocationIdMalformed)),
                    "{raw:?}: {observed:?}"
                );
            }
        }
        for other in [vec![0x22; 16], one_bit.to_vec()] {
            let unit = UnitFixture::new(vec![("failed".to_owned(), other.clone())]);
            let observed =
                read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
            assert!(
                matches!(observed, Err(SystemdUnitResultError::InvocationMismatch)),
                "{other:?}: {observed:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_unit_that_changes_around_the_snapshot_is_refused() -> TestResult {
        let settled = ("failed".to_owned(), INVOCATION.to_vec());
        for after in [
            ("active".to_owned(), INVOCATION.to_vec()),
            ("inactive".to_owned(), INVOCATION.to_vec()),
            ("failed".to_owned(), vec![0x22; 16]),
        ] {
            let unit = UnitFixture::new(vec![settled.clone(), after.clone()]);
            let observed =
                read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
            assert!(
                matches!(observed, Err(SystemdUnitResultError::StateChanged)),
                "{after:?}: {observed:?}"
            );
        }
        let unit = UnitFixture::new(vec![("active".to_owned(), INVOCATION.to_vec()), settled]);
        let observed = read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
        assert!(matches!(
            observed,
            Err(SystemdUnitResultError::NotSettled { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn missing_properties_and_snapshots_are_typed_errors() -> TestResult {
        for property in ["Result", "ExecMainCode", "ExecMainStatus"] {
            let mut service = ServiceFixture::new("success", CLD_EXITED, 0);
            service.failing = Some(property);
            let observed = read_from(UnitFixture::new(failed()), Some(service)).await?;
            assert_property(&observed, property);
        }
        for property in ["ActiveState", "InvocationID"] {
            let mut unit = UnitFixture::new(failed());
            unit.failing = Some(property);
            let observed =
                read_from(unit, Some(ServiceFixture::new("success", CLD_EXITED, 0))).await?;
            assert_property(&observed, property);
        }
        let no_service = read_from(UnitFixture::new(failed()), None::<ServiceFixture>).await?;
        assert_property(&no_service, SERVICE_INTERFACE);
        Ok(())
    }

    #[tokio::test]
    async fn wrongly_typed_properties_are_typed_errors() -> TestResult {
        let observed = read_from(
            UnitFixture::new(failed()),
            Some(WrongService("success".to_owned())),
        )
        .await?;
        assert_property(&observed, "Result");
        let observed = read_from(
            UnitFixture::new(failed()),
            Some(WrongCodeService("success".to_owned())),
        )
        .await?;
        assert_property(&observed, "ExecMainCode");
        let service = WrongStatusService(ServiceFixture::new("success", CLD_EXITED, 0));
        let observed = read_from(UnitFixture::new(failed()), Some(service)).await?;
        assert_property(&observed, "ExecMainStatus");
        let service = || Some(ServiceFixture::new("success", CLD_EXITED, 0));
        let observed = read_from(WrongStateUnit(b"failed".to_vec()), service()).await?;
        assert_property(&observed, "ActiveState");
        let observed = read_from(WrongInvocationUnit("failed".to_owned()), service()).await?;
        assert_property(&observed, "InvocationID");
        Ok(())
    }

    #[tokio::test]
    async fn another_unit_object_is_never_read() -> TestResult {
        let (_server, client) = peer_connections(|server| {
            server
                .serve_at(UNIT_PATH, UnitFixture::new(failed()))
                .serve_at(UNIT_PATH, ServiceFixture::new("success", CLD_EXITED, 0))
        })
        .await?;
        let transport = SystemdTransientUnitTransport { connection: client };
        let mut other = started()?;
        other.unit_path = OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/other")?;
        assert_property(
            &transport.read_unit_result(&other, INVOCATION).await,
            UNIT_INTERFACE,
        );
        let started = started()?;
        assert!(transport
            .read_unit_result(&started, INVOCATION)
            .await
            .is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn a_proxy_construction_failure_is_classified() -> TestResult {
        let failed = Err(zbus::Error::InvalidField);
        assert!(matches!(
            read_with_proxy(failed, &started()?, INVOCATION).await,
            Err(SystemdUnitResultError::Proxy(zbus::Error::InvalidField))
        ));
        Ok(())
    }
}
