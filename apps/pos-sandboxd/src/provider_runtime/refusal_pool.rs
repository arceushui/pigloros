//! The bounded pool of uncharged readers (ADR-069 R11 Amendment 1 §7.5 and
//! item P7).
//!
//! Every read the ledger does not charge shares this pool: the refusal
//! reads of a full worker pool, every read while the runtime is `Starting`
//! or `ReconcileFailed`, and the hand-off of a connection whose source
//! charge the ledger refused. At most `max(bound, 1)` run at once, so every
//! uncharged allocation stays bounded. A waiting hand-off is served before
//! any new read: while one waits the pool reports no room, and the acceptor
//! does not poll the execute listener.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// The pool of at most `max(bound, 1)` uncharged readers.
#[derive(Debug)]
pub(super) struct RefusalPool {
    bound: usize,
    state: Mutex<Readers>,
    freed: Condvar,
}

/// The running readers and the connections waiting for one.
#[derive(Debug, Default)]
struct Readers {
    running: usize,
    waiting: usize,
}

/// One running uncharged reader; dropping it frees its place.
#[derive(Debug)]
pub(super) struct ReaderPermit<'p>(&'p RefusalPool);

impl Drop for ReaderPermit<'_> {
    fn drop(&mut self) {
        self.0.readers().running -= 1;
        self.0.freed.notify_all();
    }
}

impl RefusalPool {
    /// The pool of a worker pool of `bound`: at most `max(bound, 1)`.
    pub(super) fn new(bound: usize) -> Self {
        Self {
            bound: bound.max(1),
            state: Mutex::new(Readers::default()),
            freed: Condvar::new(),
        }
    }

    fn readers(&self) -> MutexGuard<'_, Readers> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a new connection could start reading now: a place is free
    /// and no connection waits for one.
    pub(super) fn has_room(&self) -> bool {
        let readers = self.readers();
        readers.waiting == 0 && readers.running < self.bound
    }

    /// Wait for a place until `until`, ahead of any new read; `None` once
    /// `until` passed with no place free.
    pub(super) fn wait(&self, until: Instant) -> Option<ReaderPermit<'_>> {
        let mut readers = self.readers();
        readers.waiting += 1;
        loop {
            if readers.running < self.bound {
                readers.waiting -= 1;
                readers.running += 1;
                return Some(ReaderPermit(self));
            }
            let Some(left) = until
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                readers.waiting -= 1;
                return None;
            };
            readers = self
                .freed
                .wait_timeout(readers, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn at_most_max_bound_one_read_at_once_and_a_waiter_blocks_new_reads() {
        // A worker pool of 0 still has one uncharged reader.
        let pool = RefusalPool::new(0);
        assert!(pool.has_room());
        let soon = || Instant::now() + Duration::from_millis(30);
        let first = pool.wait(soon());
        assert!(first.is_some());
        assert!(!pool.has_room());
        // A second waits until its deadline and gets nothing.
        assert!(pool.wait(soon()).is_none());
        assert!(pool.wait(Instant::now()).is_none());
        std::thread::scope(|scope| {
            let waiter =
                scope.spawn(|| pool.wait(Instant::now() + Duration::from_secs(5)).is_some());
            // While it waits, no new read is admitted.
            while pool.readers().waiting == 0 {
                std::thread::yield_now();
            }
            assert!(!pool.has_room());
            drop(first);
            assert!(waiter.join().unwrap_or(false));
        });
        // Its permit was dropped with the thread: the place is free again.
        assert!(pool.has_room());
        let pool = RefusalPool::new(2);
        let held = (pool.wait(soon()), pool.wait(soon()));
        assert!(held.0.is_some() && held.1.is_some());
        assert!(!pool.has_room());
        drop(held);
        assert!(pool.has_room());
    }
}
