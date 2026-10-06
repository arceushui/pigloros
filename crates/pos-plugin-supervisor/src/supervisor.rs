//! One supervised invocation in a fresh worker (ADR-061 revision 4).
//!
//! Every call to [`CommunityPluginSupervisorV1::describe`],
//! [`CommunityPluginSupervisorV1::reduce`] or
//! [`CommunityPluginSupervisorV1::drive`] launches a new worker process, sends
//! it exactly one request frame, reads at most one response frame, and reaps
//! the worker. Nothing is retried: a later operator retry is a new invocation.
//!
//! Outcomes are classified in this order:
//! 1. An invocation outside its WIT bounds, or a request the IPC cannot
//!    carry, is `InvalidInvocation`, and no worker starts.
//! 2. The wall-time watchdog: when the deadline passes before the worker has
//!    replied and exited, the supervisor kills it and reports the operational
//!    `OperationalWatchdogStop`. The worker's own epoch watchdog reports the
//!    same error. It never substitutes for `FuelExhausted`.
//! 3. A worker that cannot start or be confined, dies, is signalled, exits
//!    unsuccessfully, closes its output early, or sends a truncated,
//!    over-limit, trailing, malformed, non-canonical or mismatched frame or
//!    envelope is the operational `WorkerCrashed`. Nothing is fabricated from
//!    it.
//! 4. A well-formed response reports the engine's closed failure or trap
//!    class, or the guest's return. A returned value that fails the
//!    supervisor's own checks ([`crate::verify`]) is the authoritative
//!    `InvalidGuestOutput`.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, HostInputs, InvocationReportV1, NegotiatedCommunityPluginV1,
    PluginDescriptorV1, PluginInvocationV1, PluginOutputV1,
};

use crate::frame::{read_frame, require_end, write_frame, FrameFaultV1, WorkerFrameLimitsV1};
use crate::ipc::{
    decode_worker_response_v1, encode_worker_request_v1, WorkerCallV1, WorkerRequestV1,
    WorkerReturnV1,
};
use crate::launch::{launch, LaunchedWorker, WorkerProgramV1, WorkerResourceCeilingsV1};
use crate::verify::{verify_descriptor, verify_output};

/// The longest wall-time watchdog a supervisor accepts.
pub const MAX_WORKER_WATCHDOG: Duration = Duration::from_hours(1);
/// Interval at which the supervisor checks whether a replied worker exited.
const EXIT_POLL: Duration = Duration::from_millis(1);

type Error = CommunityPluginHostErrorV1;

/// Launches one fresh worker per invocation under a wall-time watchdog.
///
/// This is the ADR-061 revision 4 Local relaxation: engineering evidence, not
/// a hosted, Candidate or Stable execution boundary, and no hosted
/// conformance claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginSupervisorV1 {
    program: WorkerProgramV1,
    watchdog: Duration,
}

impl CommunityPluginSupervisorV1 {
    /// A supervisor launching `program` with a `watchdog` wall-time deadline.
    ///
    /// Returns `None` for a zero watchdog or one above
    /// [`MAX_WORKER_WATCHDOG`].
    #[must_use]
    pub fn new(program: WorkerProgramV1, watchdog: Duration) -> Option<Self> {
        (!watchdog.is_zero() && watchdog <= MAX_WORKER_WATCHDOG)
            .then_some(Self { program, watchdog })
    }

    /// The wall-time watchdog, measured from the worker's launch.
    #[must_use]
    pub const fn watchdog(&self) -> Duration {
        self.watchdog
    }

    /// Call `describe` in a fresh worker.
    ///
    /// # Errors
    /// Returns the closed error that ended the invocation (see the module
    /// documentation), or `InvalidGuestOutput` when the descriptor does not
    /// describe `negotiated`.
    pub fn describe(
        &self,
        negotiated: &NegotiatedCommunityPluginV1,
        component: &[u8],
        host_inputs: HostInputs,
    ) -> Result<InvocationReportV1<PluginDescriptorV1>, Error> {
        match self.run(negotiated, component, host_inputs, WorkerCallV1::Describe)? {
            WorkerReturnV1::Described(report) => {
                checked(report, |descriptor| verify_descriptor(descriptor, negotiated))
            }
            WorkerReturnV1::Produced(_) => Err(Error::WorkerCrashed),
        }
    }

    /// Call `reduce` with `invocation` in a fresh worker.
    ///
    /// # Errors
    /// Returns `InvalidInvocation` before any worker starts for an invocation
    /// outside its WIT bounds, then the closed error that ended the
    /// invocation, or `InvalidGuestOutput` when the output fails the
    /// supervisor's checks.
    pub fn reduce(
        &self,
        negotiated: &NegotiatedCommunityPluginV1,
        component: &[u8],
        invocation: &PluginInvocationV1,
        host_inputs: HostInputs,
    ) -> Result<InvocationReportV1<PluginOutputV1>, Error> {
        invocation.validate()?;
        let call = WorkerCallV1::Reduce(invocation.clone());
        let outcome = self.run(negotiated, component, host_inputs, call)?;
        produced(outcome, negotiated, invocation)
    }

    /// Call `drive` with `invocation` in a fresh worker.
    ///
    /// # Errors
    /// As [`Self::reduce`].
    pub fn drive(
        &self,
        negotiated: &NegotiatedCommunityPluginV1,
        component: &[u8],
        invocation: &PluginInvocationV1,
        host_inputs: HostInputs,
    ) -> Result<InvocationReportV1<PluginOutputV1>, Error> {
        invocation.validate()?;
        let call = WorkerCallV1::Drive(invocation.clone());
        let outcome = self.run(negotiated, component, host_inputs, call)?;
        produced(outcome, negotiated, invocation)
    }

    /// Run one call in a fresh worker and decode its response.
    fn run(
        &self,
        negotiated: &NegotiatedCommunityPluginV1,
        component: &[u8],
        host_inputs: HostInputs,
        call: WorkerCallV1,
    ) -> Result<WorkerReturnV1, Error> {
        let limits = negotiated.limits().values();
        let request = WorkerRequestV1 {
            component: component.to_vec(),
            negotiation: negotiated.to_transport(),
            watchdog_millis: u64::try_from(self.watchdog.as_millis()).unwrap_or(u64::MAX),
            host_inputs,
            call,
        };
        let request = encode_worker_request_v1(&request).map_err(|_| Error::InvalidInvocation)?;
        let ceilings = WorkerResourceCeilingsV1::for_invocation(&limits, self.watchdog);
        let deadline = Instant::now() + self.watchdog;
        let worker = launch(&self.program, &ceilings).ok_or(Error::WorkerCrashed)?;
        let frames = WorkerFrameLimitsV1::for_limits(&limits);
        let response = supervise(worker, &request, frames, deadline)?;
        decode_worker_response_v1(&response).map_err(|_| Error::WorkerCrashed)?
    }
}

/// The output report of a `reduce` or `drive` outcome, checked.
fn produced(
    outcome: WorkerReturnV1,
    negotiated: &NegotiatedCommunityPluginV1,
    invocation: &PluginInvocationV1,
) -> Result<InvocationReportV1<PluginOutputV1>, Error> {
    let limits = negotiated.limits().values();
    match outcome {
        WorkerReturnV1::Produced(report) => {
            checked(report, |output| verify_output(output, invocation, &limits))
        }
        WorkerReturnV1::Described(_) => Err(Error::WorkerCrashed),
    }
}

/// `report`, unless its value fails `verify`.
///
/// The guest's own `plugin-error` is passed through: the engine validated it.
fn checked<T>(
    report: InvocationReportV1<T>,
    verify: impl FnOnce(&T) -> bool,
) -> Result<InvocationReportV1<T>, Error> {
    let valid = report.result.as_ref().ok().is_none_or(verify);
    if valid {
        Ok(report)
    } else {
        Err(Error::InvalidGuestOutput)
    }
}

/// How the worker side of one invocation ended.
enum Ending {
    /// One complete frame, then end of output, then a successful exit.
    Replied(Vec<u8>),
    /// The worker or its IPC failed.
    Crashed,
    /// The deadline passed first.
    TimedOut,
}

/// Exchange the request and response with `worker` before `deadline`.
///
/// Both pipe ends are served on scoped threads, so a worker that neither reads
/// nor writes cannot block the supervisor past the deadline. The worker is
/// killed and reaped before this returns.
fn supervise(
    worker: LaunchedWorker,
    request: &[u8],
    frames: WorkerFrameLimitsV1,
    deadline: Instant,
) -> Result<Vec<u8>, CommunityPluginHostErrorV1> {
    let LaunchedWorker {
        mut process,
        mut stdin,
        mut stdout,
    } = worker;
    let (sender, receiver) = mpsc::channel();
    let ending = thread::scope(|scope| {
        scope.spawn(move || {
            // A worker that stops reading fails on its own; the reply decides.
            let _written = write_frame(&mut stdin, request, WorkerFrameLimitsV1::REQUEST_BYTES);
        });
        scope.spawn(move || {
            let reply = read_frame(&mut stdout, frames.response_bytes())
                .and_then(|bytes| require_end(&mut stdout).map(|()| bytes));
            drop(sender.send(reply));
        });
        let ending = await_reply(&receiver, &mut process.child, deadline);
        process.stop();
        ending
    });
    match ending {
        Ending::Replied(bytes) => Ok(bytes),
        Ending::Crashed => Err(CommunityPluginHostErrorV1::WorkerCrashed),
        Ending::TimedOut => Err(CommunityPluginHostErrorV1::OperationalWatchdogStop),
    }
}

fn await_reply(
    receiver: &mpsc::Receiver<Result<Vec<u8>, FrameFaultV1>>,
    child: &mut std::process::Child,
    deadline: Instant,
) -> Ending {
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(bytes)) => await_exit(child, deadline).map_or(Ending::TimedOut, |success| {
            if success {
                Ending::Replied(bytes)
            } else {
                Ending::Crashed
            }
        }),
        Ok(Err(_)) => Ending::Crashed,
        Err(_) => Ending::TimedOut,
    }
}

/// Whether the worker exited successfully, or `None` if it still runs at
/// `deadline`.
fn await_exit(child: &mut std::process::Child, deadline: Instant) -> Option<bool> {
    loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            return Some(status.success());
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(EXIT_POLL);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::path::PathBuf;

    use pos_runtime::community_plugin_host::{
        GuestPluginErrorV1, MeteringV1, PluginErrorCodeV1,
    };

    use super::*;

    fn report<T>(result: Result<T, GuestPluginErrorV1>) -> InvocationReportV1<T> {
        InvocationReportV1 {
            result,
            metering: MeteringV1 {
                startup_fuel: 1,
                call_fuel: 2,
                memory_bytes: 3,
                host_calls: 4,
            },
            operational_log: Vec::new(),
        }
    }

    #[test]
    fn returned_values_must_pass_the_supervisor_check() {
        assert_eq!(checked(report(Ok(1)), |value| *value == 1), Ok(report(Ok(1))));
        assert_eq!(
            checked(report(Ok(2)), |value| *value == 1),
            Err(Error::InvalidGuestOutput)
        );
        let guest = GuestPluginErrorV1 {
            code: PluginErrorCodeV1::DeterministicBudgetExhausted,
            canonical_coordinate: None,
            related_digest: None,
        };
        let declared = report::<u8>(Err(guest));
        assert_eq!(checked(declared.clone(), |_| false), Ok(declared));
    }

    #[test]
    fn watchdogs_must_be_positive_and_bounded() {
        let program = WorkerProgramV1::new(PathBuf::from("/worker"));
        let supervisor = |watchdog| {
            program
                .clone()
                .and_then(|program| CommunityPluginSupervisorV1::new(program, watchdog))
        };
        assert!(supervisor(Duration::ZERO).is_none());
        assert!(supervisor(MAX_WORKER_WATCHDOG + Duration::from_nanos(1)).is_none());
        let longest = supervisor(MAX_WORKER_WATCHDOG);
        assert_eq!(
            longest.map(|supervisor| supervisor.watchdog()),
            Some(MAX_WORKER_WATCHDOG)
        );
        assert!(supervisor(Duration::from_nanos(1)).is_some());
    }
}
