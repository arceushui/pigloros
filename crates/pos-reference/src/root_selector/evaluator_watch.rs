//! Watching the evaluator connection while its provider attempt runs
//! (owner decision on #1503: SCQ1 when the evaluator drops after AGR1).
//!
//! The evaluator socket is idle during an execute: the request was read in
//! full, and the evaluator waits for the reply. A peer that closed its end
//! entirely raises `POLLHUP` on this end; a peer that only shut down its write
//! side (the normal state) raises no `POLLHUP`, so `events = 0` is enough.
//!
//! Limits, by design:
//! - An evaluator that times out and gives up is detected only when it closes
//!   its socket. A silent evaluator that keeps the connection open is never
//!   detected here; the provider attempt then ends under its own watchdog.
//! - The watch is only sound while the selector keeps its own end open for
//!   writing: shutting down the selector's write side after the peer's
//!   half-close raises `POLLHUP` on the same socket and would cancel every
//!   normal attempt. [`execute_watched`] joins the watcher before it returns,
//!   and the selector shuts down only after that.

use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::recovery_pending::report_diagnostic;
use super::{io_error, DiagnosticSink};
use crate::selector::SelectorBoundaryError;

/// The provider attempt of one request: whether its AGR1 was authenticated
/// and whether its execute exchange has ended.
#[derive(Default)]
pub(super) struct InFlightAttempt {
    state: Mutex<AttemptState>,
    changed: Condvar,
    /// Watchers blocked on `changed`, so a test can wait for one to arrive.
    #[cfg(test)]
    waiting: AtomicUsize,
}

#[derive(Default)]
struct AttemptState {
    agr1_digest: Option<[u8; 32]>,
    finished: bool,
}

impl InFlightAttempt {
    fn state(&self) -> MutexGuard<'_, AttemptState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The transport authenticated this AGR1.
    pub(super) fn granted(&self, agr1_digest: [u8; 32]) {
        self.state().agr1_digest = Some(agr1_digest);
        self.changed.notify_all();
    }

    /// How many watchers wait for a grant right now.
    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }

    /// The execute exchange ended: nothing is left to cancel from here.
    pub(super) fn finish(&self) {
        self.state().finished = true;
        self.changed.notify_all();
    }

    /// The AGR1 of a still running attempt, once there is one; `None` when
    /// the exchange ended first.
    fn wait_for_running_grant(&self) -> Option<[u8; 32]> {
        let mut state = self.state();
        while state.agr1_digest.is_none() && !state.finished {
            #[cfg(test)]
            self.waiting.fetch_add(1, Ordering::Release);
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
            #[cfg(test)]
            self.waiting.fetch_sub(1, Ordering::Release);
        }
        let running = (!state.finished).then_some(state.agr1_digest);
        drop(state);
        running.flatten()
    }
}

/// Whether `evaluator` closed its end entirely before `wake` became ready or
/// closed. `timeout` bounds the wait; production waits indefinitely.
fn wait_for_hang_up(
    evaluator: &UnixStream,
    wake: &UnixStream,
    timeout: Option<&Timespec>,
) -> rustix::io::Result<bool> {
    let mut descriptors = [
        PollFd::new(evaluator, PollFlags::empty()),
        PollFd::new(wake, PollFlags::IN),
    ];
    rustix::io::retry_on_intr(|| poll(&mut descriptors, timeout)).map(|_| {
        descriptors[1].revents().is_empty()
            && descriptors[0]
                .revents()
                .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    })
}

/// Cancel the attempt once the evaluator hung up while it runs; report a
/// failed poll, which ends the watch, to `diagnostics`.
fn watch_evaluator(
    evaluator: &UnixStream,
    wake: &UnixStream,
    timeout: Option<&Timespec>,
    in_flight: &InFlightAttempt,
    cancel: impl FnOnce([u8; 32]),
    diagnostics: &DiagnosticSink,
) {
    match wait_for_hang_up(evaluator, wake, timeout) {
        Ok(hung_up) => {
            let running = hung_up
                .then(|| in_flight.wait_for_running_grant())
                .flatten();
            if let Some(agr1_digest) = running {
                cancel(agr1_digest);
            }
        }
        Err(errno) => report_diagnostic(diagnostics, "evaluator watch failed", &errno),
    }
}

/// Run `execute` while a scoped thread watches `evaluator`. If the evaluator
/// hangs up while an attempt with an authenticated AGR1 runs, `cancel` is
/// called with that AGR1 digest, concurrently with `execute`. A poll failure
/// goes to `diagnostics`. The watcher is always woken and joined, also when
/// `execute` panics, which then continues to unwind.
///
/// A panic in the watcher thread (that is, in `cancel`) is raised by the
/// scope after `execute` returned: the result of `execute` is discarded and
/// the caller's later steps, including SRQ1, never run. That is fail-closed
/// and fatal for the connection handler; the namespace lease held by
/// `execute_ordered` is not released either (it is not on a panic path).
///
/// # Errors
/// Fails closed, before `execute` runs, when the wake pair or the watcher
/// thread cannot be created.
pub(super) fn execute_watched<R>(
    evaluator: &UnixStream,
    in_flight: &InFlightAttempt,
    cancel: impl Fn([u8; 32]) + Sync,
    diagnostics: &DiagnosticSink,
    execute: impl FnOnce() -> R,
) -> Result<R, SelectorBoundaryError> {
    UnixStream::pair()
        .map_err(io_error)
        .and_then(|(wake, woken)| {
            thread::scope(|scope| {
                thread::Builder::new()
                    .spawn_scoped(scope, || {
                        watch_evaluator(evaluator, &woken, None, in_flight, &cancel, diagnostics);
                    })
                    .map_err(io_error)
                    .map(|_watcher| {
                        // `AssertUnwindSafe` is sound here: after a panic `execute`
                        // is never called again, and its captures are only
                        // observed through the re-raised panic. State captured by
                        // reference (the admission lease, `in_flight`) is not
                        // torn: its destructors run during the unwind, and each
                        // takes its lock or releases its own count independently.
                        let outcome = catch_unwind(AssertUnwindSafe(execute));
                        in_flight.finish();
                        drop(wake);
                        outcome.unwrap_or_else(|panic| resume_unwind(panic))
                    })
            })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
