//! The per-navigation served count shared between the accept threads and the driver.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ServedSnapshot;

/// Counts completed owner-document responses for the current navigation.
#[derive(Debug, Default)]
pub struct ServedLedger {
    count: AtomicU32,
    integrity_failed: AtomicBool,
}

impl ServedLedger {
    /// Reset the count and verdict because a new navigation begins.
    pub fn reset(&self) {
        self.count.store(0, Ordering::SeqCst);
        self.integrity_failed.store(false, Ordering::SeqCst);
    }

    /// Record one completed owner response and whether its digest matched.
    pub fn complete(&self, digest_ok: bool) {
        if !digest_ok {
            self.integrity_failed.store(true, Ordering::SeqCst);
        }
        self.count.fetch_add(1, Ordering::SeqCst);
    }

    /// Return the current count and integrity verdict.
    #[must_use]
    pub fn snapshot(&self) -> ServedSnapshot {
        ServedSnapshot {
            count: self.count.load(Ordering::SeqCst),
            integrity_ok: !self.integrity_failed.load(Ordering::SeqCst),
        }
    }
}
