//! The one `CLOCK_MONOTONIC` reader of the provider binary.
//!
//! It lives in the launcher so that the launcher, which may reach nothing
//! outside its own module (owner decision Q9.11), and the rest of the
//! provider share it.

use std::io;

use rustix::time::{clock_gettime, ClockId, Timespec};

/// The current `CLOCK_MONOTONIC` time in nanoseconds.
///
/// # Errors
/// `InvalidData` for a time the clock cannot report in unsigned
/// nanoseconds, such as a negative one.
pub(crate) fn monotonic_ns() -> io::Result<u64> {
    timespec_ns(clock_gettime(ClockId::Monotonic))
}

/// `now` in nanoseconds.
///
/// # Errors
/// `InvalidData` for a negative time or one beyond `u64` nanoseconds.
fn timespec_ns(now: Timespec) -> io::Result<u64> {
    u64::try_from(now.tv_sec)
        .ok()
        .zip(u64::try_from(now.tv_nsec).ok())
        .and_then(|(seconds, nanoseconds)| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|whole| whole.checked_add(nanoseconds))
        })
        .ok_or(io::ErrorKind::InvalidData)
        .map_err(io::Error::from)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn a_negative_or_overflowing_clock_time_is_invalid_data() {
        let at = |tv_sec: i64, tv_nsec: i64| {
            super::timespec_ns(super::Timespec { tv_sec, tv_nsec }).map_err(|error| error.kind())
        };
        assert_eq!(at(0, 0), Ok(0));
        assert_eq!(at(1, 5), Ok(1_000_000_005));
        assert_eq!(at(18_446_744_073, 709_551_615), Ok(u64::MAX));
        for (seconds, nanoseconds) in [
            (-1, 0),
            (0, -1),
            (i64::MAX, 0),
            (18_446_744_073, 709_551_616),
        ] {
            assert_eq!(
                at(seconds, nanoseconds),
                Err(std::io::ErrorKind::InvalidData),
                "{seconds} s {nanoseconds} ns"
            );
        }
    }
}
