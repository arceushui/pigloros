//! Deterministic time and randomness.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::{MonotonicClock, SecureRandom, UnavailableCode};

/// Reports the earliest moment, as an offset from clock start, at which something outside the
/// ceremony (a scheduled surface event or a page task) will happen.
pub type ActivitySource = Box<dyn Fn() -> Option<Duration>>;

struct ClockState {
    base: Cell<Instant>,
    offset: Cell<Duration>,
    activity: RefCell<Option<ActivitySource>>,
}

/// A shared fake monotonic clock that only moves when a test or the fake stepper advances it.
#[derive(Clone)]
pub struct FakeClock {
    state: Rc<ClockState>,
}

impl FakeClock {
    /// Start a clock at offset zero.
    #[must_use]
    pub fn start() -> Self {
        Self {
            state: Rc::new(ClockState {
                base: Cell::new(Instant::now()),
                offset: Cell::new(Duration::ZERO),
                activity: RefCell::new(None),
            }),
        }
    }

    /// Install the source of the next outside activity that `skip` must not jump over.
    pub fn set_activity_source(&self, source: ActivitySource) {
        *self.state.activity.borrow_mut() = Some(source);
    }

    /// Advance the clock by `duration`.
    pub fn advance(&self, duration: Duration) {
        self.state.offset.set(self.state.offset.get() + duration);
    }

    /// Shift the clock's origin so that its current time is exactly `instant`, keeping the elapsed
    /// time (and so every scheduled offset) unchanged. A host calls this with a ceremony's T0
    /// when the owner thread drew it from another clock, so the ceremony's bounds do not depend on
    /// how the two clocks' origins happen to be scheduled.
    ///
    /// An `Instant` cannot go back past the platform's epoch, so for an instant closer to it than
    /// the elapsed time the origin becomes the instant itself.
    pub fn align_to(&self, instant: Instant) {
        let origin = instant
            .checked_sub(self.state.offset.get())
            .unwrap_or(instant);
        self.state.base.set(origin);
    }

    /// How far `instant` is from the clock's start (zero for an earlier instant).
    #[must_use]
    pub fn offset_of(&self, instant: Instant) -> Duration {
        instant.saturating_duration_since(self.state.base.get())
    }

    /// The time elapsed since the clock started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.state.offset.get()
    }
}

impl FakeClock {
    /// Move time forward by one timer interval, or skip dead time up to the next instant at which
    /// anything can happen: the driver's `wake` or the next scheduled surface or page activity.
    pub fn skip(&self, interval: Duration, wake: Option<Instant>) {
        let now = self.state.base.get() + self.state.offset.get();
        let until_wake = wake.map(|instant| instant.saturating_duration_since(now));
        let activity = self.state.activity.borrow();
        let until_activity = activity
            .as_ref()
            .and_then(|source| source())
            .map(|at| at.saturating_sub(self.state.offset.get()));
        let gap = [until_wake, until_activity].into_iter().flatten().min();
        self.advance(gap.map_or(interval, |gap| gap.max(interval)));
    }
}

impl MonotonicClock for FakeClock {
    fn now(&self) -> Instant {
        self.state.base.get() + self.state.offset.get()
    }
}

/// A deterministic random source: `SplitMix64` bytes, optionally failing after some fills.
#[derive(Clone, Debug)]
pub struct FakeRandom {
    state: u64,
    fills_before_failure: Option<u32>,
}

impl FakeRandom {
    /// A source that never fails, seeded with `seed`.
    #[must_use]
    pub const fn seeded(seed: u64) -> Self {
        Self {
            state: seed,
            fills_before_failure: None,
        }
    }

    /// A source that fails every fill after `fills` successful ones.
    #[must_use]
    pub const fn failing_after(seed: u64, fills: u32) -> Self {
        Self {
            state: seed,
            fills_before_failure: Some(fills),
        }
    }

    const fn next_word(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut word = self.state;
        word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        word ^ (word >> 31)
    }
}

impl SecureRandom for FakeRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        if let Some(fills) = self.fills_before_failure {
            if fills == 0 {
                return Err(UnavailableCode::RngUnavailable);
            }
            self.fills_before_failure = Some(fills - 1);
        }
        for chunk in out.chunks_mut(8) {
            let word = self.next_word().to_le_bytes();
            let (head, _) = word.split_at(chunk.len());
            chunk.copy_from_slice(head);
        }
        Ok(())
    }
}
