//! Production randomness and time ports (ADR-110 §6).

use std::time::{Duration, Instant};

use crate::UnavailableCode;

/// A source of cryptographically secure random bytes.
pub trait SecureRandom {
    /// Fill `out` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`UnavailableCode::RngUnavailable`] when randomness cannot be produced.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode>;
}

/// A monotonic clock that can also pause the calling thread.
pub trait MonotonicClock {
    /// Return the current monotonic instant.
    fn now(&self) -> Instant;

    /// Block for `duration`; tests advance a fake clock instead.
    fn pause(&self, duration: Duration);

    /// Pause for one pump interval. `wake` is the next instant at which the ceremony itself
    /// needs attention (`_wake`). A real clock ignores it, because surface events must be polled at the
    /// pump interval; a fake clock may skip ahead to it when nothing else can happen sooner.
    fn pause_for(&self, interval: Duration, _wake: Option<Instant>) {
        self.pause(interval);
    }
}

/// The operating-system CSPRNG (`getrandom`).
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl SecureRandom for OsRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        getrandom::fill(out).or(Err(UnavailableCode::RngUnavailable))
    }
}

/// The production monotonic clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn pause(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}
