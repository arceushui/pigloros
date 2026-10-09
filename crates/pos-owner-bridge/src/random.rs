//! Production randomness and time ports (ADR-110 §6).

use std::time::Instant;

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

/// A monotonic clock. The portable core only reads it; it never sleeps (ADR-110 §6, §10): the
/// host owns the timer and its callbacks.
pub trait MonotonicClock {
    /// Return the current monotonic instant.
    fn now(&self) -> Instant;
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
}
