//! One supervised invocation in a fresh worker (ADR-061 revision 4).
//!
//! Every call to [`CommunityPluginSupervisorV1::invoke`] launches a new worker
//! process, sends it exactly one request frame, reads at most one response
//! frame, and reaps the worker. Nothing is retried: a later operator retry is a
//! new invocation.
//!
//! Outcomes are classified in this order:
//! 1. A request the host cannot encode is `InvalidInvocation`, and no worker
//!    starts.
//! 2. The wall-time watchdog: when the deadline passes before the worker has
//!    replied and exited, the supervisor kills it and reports the operational
//!    `OperationalWatchdogStop`. It never substitutes for `FuelExhausted`.
//! 3. A worker that cannot start or be confined, dies, is signalled, exits
//!    unsuccessfully, closes its output early, or sends a truncated,
//!    over-limit, trailing, malformed or non-canonical frame or envelope is
//!    the operational `WorkerCrashed`. Nothing is fabricated from it.
//! 4. A well-formed response reports the engine's closed failure or trap
//!    class, or a guest payload. A payload that the host's validator rejects
//!    is the authoritative `InvalidGuestOutput`.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use pos_crypto::plugin_worker_ipc::{
    decode_worker_response_v1, encode_worker_request_v1, WorkerCompletionV1, WorkerExportV1,
    WorkerFailureV1, WorkerNegotiationV1, WorkerOutcomeV1, WorkerRequestV1, WorkerTrapClassV1,
};
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, ComponentTrapClassV1, NegotiatedCommunityPluginV1,
    TrapReproductionV1,
};

use crate::frame::{read_frame, require_end, write_frame, FrameFaultV1, WorkerFrameLimitsV1};
use crate::launch::{launch, LaunchedWorker, WorkerProgramV1, WorkerResourceCeilingsV1};

/// The longest wall-time watchdog a supervisor accepts.
pub const MAX_WORKER_WATCHDOG: Duration = Duration::from_hours(1);
/// Interval at which the supervisor checks whether a replied worker exited.
const EXIT_POLL: Duration = Duration::from_millis(1);

/// One invocation's inputs besides the negotiated release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerInvocationV1<'a> {
    /// The export to invoke.
    pub export: WorkerExportV1,
    /// The verified Component bytes.
    pub component: &'a [u8],
    /// Simulation Time that `simulation-time` returns.
    pub simulation_time: u64,
    /// The canonical `plugin-invocation` record; empty for `describe`.
    pub invocation: &'a [u8],
}

/// The validated guest output and the measured budget of one invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReportV1<T> {
    /// The guest output, as accepted by the host's validator.
    pub output: T,
    /// Fuel consumed while instantiating the Component.
    pub startup_fuel: u64,
    /// Fuel consumed by the call itself.
    pub call_fuel: u64,
    /// Linear memory reserved by the Component, in bytes.
    pub memory_bytes: u64,
}

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

    /// Run one invocation of `negotiated` in a fresh worker.
    ///
    /// `validate` receives a completed call's guest payload and returns the
    /// validated output, or `None` to reject it.
    ///
    /// # Errors
    /// Returns `InvalidInvocation` when the request exceeds the IPC bounds,
    /// `OperationalWatchdogStop` when the watchdog elapses, `WorkerCrashed`
    /// for any worker or IPC fault, `InvalidGuestOutput` when `validate`
    /// rejects the payload, and otherwise the engine's closed failure or
    /// trap class.
    pub fn invoke<T>(
        &self,
        negotiated: &NegotiatedCommunityPluginV1,
        invocation: &WorkerInvocationV1<'_>,
        validate: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<WorkerReportV1<T>, CommunityPluginHostErrorV1> {
        let limits = negotiated.limits().values();
        let request = encode_worker_request_v1(&request_envelope(negotiated, invocation))
            .map_err(|_| CommunityPluginHostErrorV1::InvalidInvocation)?;
        let ceilings = WorkerResourceCeilingsV1::for_invocation(&limits, self.watchdog);
        let deadline = Instant::now() + self.watchdog;
        let worker =
            launch(&self.program, &ceilings).ok_or(CommunityPluginHostErrorV1::WorkerCrashed)?;
        let response = supervise(
            worker,
            &request,
            WorkerFrameLimitsV1::for_limits(&limits),
            deadline,
        )?;
        decode_worker_response_v1(&response)
            .map_err(|_| CommunityPluginHostErrorV1::WorkerCrashed)
            .and_then(outcome_result)
            .and_then(|completion| report(&completion, validate))
    }
}

fn request_envelope(
    negotiated: &NegotiatedCommunityPluginV1,
    invocation: &WorkerInvocationV1<'_>,
) -> WorkerRequestV1 {
    let (abi_major, abi_minor) = negotiated.abi();
    WorkerRequestV1 {
        export: invocation.export,
        component: invocation.component.to_vec(),
        negotiation: WorkerNegotiationV1 {
            world: negotiated.world().to_owned(),
            abi_major,
            abi_minor,
            required_features: negotiated.required_features().to_vec(),
            pmf1_digest: negotiated.pmf1_digest(),
            release_digest: negotiated.release_digest(),
        },
        limits: negotiated.limits().values(),
        simulation_time: invocation.simulation_time,
        invocation: invocation.invocation.to_vec(),
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

fn outcome_result(
    outcome: WorkerOutcomeV1,
) -> Result<WorkerCompletionV1, CommunityPluginHostErrorV1> {
    match outcome {
        WorkerOutcomeV1::Completed(completion) => Ok(completion),
        WorkerOutcomeV1::Failed(failure) => Err(failure_error(failure)),
        WorkerOutcomeV1::Trapped(class) => Err(CommunityPluginHostErrorV1::ComponentTrap {
            class: trap_class(class),
            reproduction: TrapReproductionV1::Unverified,
        }),
    }
}

fn report<T>(
    completion: &WorkerCompletionV1,
    validate: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<WorkerReportV1<T>, CommunityPluginHostErrorV1> {
    validate(&completion.payload)
        .map(|output| WorkerReportV1 {
            output,
            startup_fuel: completion.startup_fuel,
            call_fuel: completion.call_fuel,
            memory_bytes: completion.memory_bytes,
        })
        .ok_or(CommunityPluginHostErrorV1::InvalidGuestOutput)
}

/// The closed host error that one in-worker failure reports.
const fn failure_error(failure: WorkerFailureV1) -> CommunityPluginHostErrorV1 {
    match failure {
        WorkerFailureV1::InvalidInvocation => CommunityPluginHostErrorV1::InvalidInvocation,
        WorkerFailureV1::IncompatibleAbi => CommunityPluginHostErrorV1::IncompatibleAbi,
        WorkerFailureV1::InvalidGuestOutput => CommunityPluginHostErrorV1::InvalidGuestOutput,
        WorkerFailureV1::FuelExhausted => CommunityPluginHostErrorV1::FuelExhausted,
        WorkerFailureV1::MemoryLimitExceeded => CommunityPluginHostErrorV1::MemoryLimitExceeded,
        WorkerFailureV1::HostCallLimitExceeded => CommunityPluginHostErrorV1::HostCallLimitExceeded,
        WorkerFailureV1::OutputLimitExceeded => CommunityPluginHostErrorV1::OutputLimitExceeded,
        WorkerFailureV1::OperationalWatchdogStop => {
            CommunityPluginHostErrorV1::OperationalWatchdogStop
        }
    }
}

/// The canonical trap class one wire class names.
const fn trap_class(class: WorkerTrapClassV1) -> ComponentTrapClassV1 {
    match class {
        WorkerTrapClassV1::Unreachable => ComponentTrapClassV1::Unreachable,
        WorkerTrapClassV1::MemoryOutOfBounds => ComponentTrapClassV1::MemoryOutOfBounds,
        WorkerTrapClassV1::TableOutOfBounds => ComponentTrapClassV1::TableOutOfBounds,
        WorkerTrapClassV1::IndirectCall => ComponentTrapClassV1::IndirectCall,
        WorkerTrapClassV1::IntegerArithmetic => ComponentTrapClassV1::IntegerArithmetic,
        WorkerTrapClassV1::StackExhausted => ComponentTrapClassV1::StackExhausted,
        WorkerTrapClassV1::Other => ComponentTrapClassV1::Other,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn failures_map_to_their_closed_host_errors() {
        let names = WorkerFailureV1::ALL.map(|failure| failure_error(failure).name());
        assert_eq!(
            names,
            [
                "InvalidInvocation",
                "IncompatibleAbi",
                "InvalidGuestOutput",
                "FuelExhausted",
                "MemoryLimitExceeded",
                "HostCallLimitExceeded",
                "OutputLimitExceeded",
                "OperationalWatchdogStop",
            ]
        );
    }

    #[test]
    fn trap_classes_map_one_to_one() {
        let classes = WorkerTrapClassV1::ALL.map(|class| trap_class(class).name());
        assert_eq!(
            classes,
            [
                "unreachable",
                "memory-out-of-bounds",
                "table-out-of-bounds",
                "indirect-call",
                "integer-arithmetic",
                "stack-exhausted",
                "other",
            ]
        );
        assert_eq!(
            outcome_result(WorkerOutcomeV1::Trapped(WorkerTrapClassV1::Other)),
            Err(CommunityPluginHostErrorV1::ComponentTrap {
                class: ComponentTrapClassV1::Other,
                reproduction: TrapReproductionV1::Unverified,
            })
        );
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
