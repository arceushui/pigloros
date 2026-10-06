//! The in-worker engine seam: the only worker code that runs a Component.
//!
//! [`invoke`] takes one decoded request and returns the outcome the worker
//! reports:
//! 1. it rebuilds the supervisor's negotiated record with
//!    `NegotiatedCommunityPluginV1::from_transport`, against this worker's V1
//!    host ABI and a profile pinning this engine's runtime, and accepts it as
//!    a `PinnedExecutionV1`. A rejected record is a protocol fault: the worker
//!    replies nothing, which the supervisor reports as `WorkerCrashed`;
//! 2. it loads the Component; a load failure is `IncompatibleAbi`;
//! 3. it calls the export under the request's limits while an epoch ticker
//!    advances the engine epoch. An invocation still running when the
//!    supervisor's watchdog has elapsed stops with `OperationalWatchdogStop`,
//!    the same error the supervisor reports when it kills a worker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use pos_plugin_host::{pinned_runtime, ComponentHost, PinnedExecutionV1};
use pos_plugin_supervisor::{WorkerCallV1, WorkerOutcomeV1, WorkerRequestV1, WorkerReturnV1};
use pos_runtime::community_plugin_host::{
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1,
    CommunityPluginHostErrorV1, InvocationOptionsV1, NegotiatedCommunityPluginV1,
    NegotiatedTransportV1,
};

/// Interval between two engine epoch increments.
pub const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Run one request, or `None` when the worker must not reply.
///
/// `None` means the engine cannot be built on this platform or the
/// transported record was rejected.
#[must_use]
pub fn invoke(request: WorkerRequestV1) -> Option<WorkerOutcomeV1> {
    ComponentHost::new()
        .ok()
        .and_then(|host| run(&host, request, EPOCH_TICK))
}

fn run(host: &ComponentHost, request: WorkerRequestV1, tick: Duration) -> Option<WorkerOutcomeV1> {
    let execution = pinned(request.negotiation)?;
    let component = match host.load(&request.component) {
        Ok(component) => component,
        Err(error) => return Some(Err(CommunityPluginHostErrorV1::from(error))),
    };
    let options = InvocationOptionsV1 {
        host_inputs: request.host_inputs,
        watchdog_epochs: watchdog_epochs(request.watchdog_millis, tick),
    };
    Some(ticking(host, tick, || match &request.call {
        WorkerCallV1::Describe => host
            .describe(&component, &execution, options)
            .map(WorkerReturnV1::Described),
        WorkerCallV1::Reduce(invocation) => host
            .reduce(&component, &execution, invocation, options)
            .map(WorkerReturnV1::Produced),
        WorkerCallV1::Drive(invocation) => host
            .drive(&component, &execution, invocation, options)
            .map(WorkerReturnV1::Produced),
    }))
}

/// The supervisor's record, rebuilt and pinned to this engine's runtime.
fn pinned(transport: NegotiatedTransportV1) -> Option<PinnedExecutionV1> {
    let profile = CommunityPluginExecutionProfileV1::new(
        transport.mode,
        CommunityPluginCeilingsV1::V1,
        pinned_runtime().ok(),
    );
    NegotiatedCommunityPluginV1::from_transport(
        transport,
        &CommunityPluginHostAbiV1::v1(),
        &profile,
    )
    .ok()
    .and_then(|negotiated| PinnedExecutionV1::new(negotiated).ok())
}

/// Epoch ticks of `tick` that fit in the supervisor's watchdog.
///
/// A tick below one millisecond counts as one millisecond.
#[must_use]
pub fn watchdog_epochs(watchdog_millis: u64, tick: Duration) -> u32 {
    let tick_millis = u64::try_from(tick.as_millis()).unwrap_or(u64::MAX).max(1);
    u32::try_from(watchdog_millis / tick_millis).unwrap_or(u32::MAX)
}

/// Run `call` while another thread advances the engine epoch every `tick`.
fn ticking<T>(host: &ComponentHost, tick: Duration, call: impl FnOnce() -> T) -> T {
    let done = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::Acquire) {
                thread::sleep(tick);
                host.increment_epoch();
            }
        });
        let result = call();
        done.store(true, Ordering::Release);
        result
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
