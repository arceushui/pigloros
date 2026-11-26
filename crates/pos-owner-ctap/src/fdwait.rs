//! Waiting for one file descriptor with a `Duration` timeout (ADR-110 E20 LS2).
//!
//! Both Linux adapters, the hidraw transport and the tty prompt, wait the same way: one
//! `poll` for input, bounded by the time left in the ceremony.

use std::os::fd::AsFd;
use std::time::Duration;

use rustix::event::{poll, Nsecs, PollFd, PollFlags, Timespec};

/// What one wait found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wait {
    /// Nothing arrived before the timeout.
    Idle,
    /// Input can be read.
    Readable,
    /// The peer is gone (hang-up or error), or the descriptor cannot be polled.
    Gone,
}

/// Wait at most `timeout` for `fd` to become readable.
///
/// A hang-up or an error condition wins over pending input, because a removed device or a closed
/// terminal must end the exchange rather than deliver a final stale report.
pub fn wait_readable(fd: &impl AsFd, timeout: Duration) -> Wait {
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let limit = Timespec {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: Nsecs::from(timeout.subsec_nanos()),
    };
    poll(&mut fds, Some(&limit)).map_or(Wait::Gone, |_| {
        let found = fds[0].revents();
        if found.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            Wait::Gone
        } else if found.contains(PollFlags::IN) {
            Wait::Readable
        } else {
            Wait::Idle
        }
    })
}
