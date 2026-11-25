//! Watching the evaluator connection while its provider attempt runs
//! (owner decision on #1503: SCQ1 when the evaluator drops after AGR1).
//!
//! The evaluator socket is idle during an execute: the request was read in
//! full, and the evaluator waits for the reply. A peer that closed its end
//! entirely raises `POLLHUP` on this end; a peer that only shut down its write
//! side (the normal state) raises no `POLLHUP`, so `events = 0` is enough.

use std::os::unix::net::UnixStream;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;

use rustix::event::{poll, PollFd, PollFlags, Timespec};

use super::io_error;
use crate::selector::SelectorBoundaryError;

/// The provider attempt of one request: whether its AGR1 was authenticated
/// and whether its execute exchange has ended.
#[derive(Default)]
pub(super) struct InFlightAttempt {
    state: Mutex<AttemptState>,
    changed: Condvar,
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
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        let running = (!state.finished).then_some(state.agr1_digest);
        drop(state);
        running.flatten()
    }
}

/// Whether `evaluator` closed its end entirely before `wake` became ready or
/// closed. `timeout` bounds the wait; production waits indefinitely.
fn wait_for_hang_up(evaluator: &UnixStream, wake: &UnixStream, timeout: Option<&Timespec>) -> bool {
    let mut descriptors = [
        PollFd::new(evaluator, PollFlags::empty()),
        PollFd::new(wake, PollFlags::IN),
    ];
    rustix::io::retry_on_intr(|| poll(&mut descriptors, timeout)).is_ok_and(|_| {
        descriptors[1].revents().is_empty()
            && descriptors[0]
                .revents()
                .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    })
}

/// Cancel the attempt once the evaluator hung up while it runs.
fn watch_evaluator(
    evaluator: &UnixStream,
    wake: &UnixStream,
    in_flight: &InFlightAttempt,
    cancel: impl FnOnce([u8; 32]),
) {
    let running = wait_for_hang_up(evaluator, wake, None)
        .then(|| in_flight.wait_for_running_grant())
        .flatten();
    if let Some(agr1_digest) = running {
        cancel(agr1_digest);
    }
}

/// Run `execute` while a scoped thread watches `evaluator`. If the evaluator
/// hangs up while an attempt with an authenticated AGR1 runs, `cancel` is
/// called with that AGR1 digest, concurrently with `execute`.
///
/// # Errors
/// Fails closed, before `execute` runs, when the watcher cannot be set up.
pub(super) fn execute_watched<R>(
    evaluator: &UnixStream,
    in_flight: &InFlightAttempt,
    cancel: impl Fn([u8; 32]) + Sync,
    execute: impl FnOnce() -> R,
) -> Result<R, SelectorBoundaryError> {
    let watched = evaluator.try_clone().map_err(io_error)?;
    let (wake, woken) = UnixStream::pair().map_err(io_error)?;
    Ok(thread::scope(|scope| {
        scope.spawn(|| watch_evaluator(&watched, &woken, in_flight, &cancel));
        let result = execute();
        in_flight.finish();
        drop(wake);
        result
    }))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
