//! Every ceremony time bound of ADR-110 §6 and the host polling cadence of §5.6.

use std::time::{Duration, Instant};

/// At most this many pairs are posted per ceremony (the first plus seven re-posts).
pub const MAX_POSTS: u8 = 8;

/// Receipt window after each post, in milliseconds: 250, 250, 500, 500, 1,000, 1,000, 2,000, 2,000.
pub const RECEIPT_WINDOWS_MS: [u64; 8] = [250, 250, 500, 500, 1_000, 1_000, 2_000, 2_000];

/// Readiness bound from T0 to the first observation past `EMPTY`.
pub const READINESS: Duration = Duration::from_secs(15);

/// How long the host re-reads a served count of zero before the document counts as unserved.
///
/// `DOMContentLoaded` can reach the host a moment before the listener records the completed
/// response, so a zero at the pre-post check is re-read at every step until this much time has
/// passed since the first zero. The window sits inside [`READINESS`], which keeps running, and a
/// zero that persists is `Unavailable(AssetIntegrity)`.
pub const SERVED_SETTLE: Duration = Duration::from_millis(100);

/// Interaction bound from the first observation past `EMPTY` to consumption.
pub const INTERACTION: Duration = Duration::from_mins(2);

/// Challenge time to live from T0.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(150);

/// Release window after the release CAS (or the illegal-state exit).
pub const RELEASE_WINDOW: Duration = Duration::from_secs(2);

/// Exit window after `Controller::Close` returns.
pub const EXIT_WINDOW: Duration = Duration::from_secs(5);

/// Total enrollment budget from E1 `Completed(ok)` through E4 `Completed(ok)`.
pub const ENROLLMENT_BUDGET: Duration = Duration::from_mins(5);

/// Poll cadence from each post and for the first second after the first observation past `EMPTY`.
pub const FAST_POLL: Duration = Duration::from_millis(10);

/// Poll cadence afterwards; the interval never grows further.
pub const SLOW_POLL: Duration = Duration::from_millis(50);

/// How long the fast cadence lasts after the first observation past `EMPTY`.
pub const FAST_POLL_SPAN: Duration = Duration::from_secs(1);

/// The cadence at which a host calls `step` while surface events must be polled: the 10 ms timer
/// of ADR-110 §6. The portable core never sleeps; the host owns this timer.
pub const TIMER_INTERVAL: Duration = FAST_POLL;

/// The receipt window of post number `post` (1-based); later posts reuse the last window.
#[must_use]
pub fn receipt_window(post: u8) -> Duration {
    let index = usize::from(post).saturating_sub(1);
    let millis = RECEIPT_WINDOWS_MS.get(index).copied().unwrap_or(2_000);
    Duration::from_millis(millis)
}

/// The poll interval, given how long ago the first observation past `EMPTY` happened.
#[must_use]
pub fn poll_interval(since_past_empty: Option<Duration>) -> Duration {
    match since_past_empty {
        Some(elapsed) if elapsed >= FAST_POLL_SPAN => SLOW_POLL,
        _ => FAST_POLL,
    }
}

/// Whether at least `limit` has passed between `since` and `now`.
#[must_use]
pub fn expired(now: Instant, since: Instant, limit: Duration) -> bool {
    now.saturating_duration_since(since) >= limit
}
