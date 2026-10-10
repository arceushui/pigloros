//! The open Tick-Boundary pass the gate runs inside (ADR-061 revision 7 decision 2).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pos_store::plugin_trust_registry::TrustedUtcSecondV1;

/// One open pass: the trusted UTC second sampled once for every member, the explicit Tick from
/// the owner of the Tick Boundary, and a pass-open flag that is cleared when the pass closes.
///
/// The gate takes these values and never reads a clock. The Tick is never read from trust
/// material, evidence or an invocation. Every authorization the gate issues shares the pass-open
/// flag, so closing the pass revokes all of them at once. Only the creator of a pass closes it.
///
/// Before the host pass seam exists the only constructor and closer are the `test-support`
/// pair: a crate-internal pair would be dead code. #584 adds the crate-internal constructor and
/// closer that the host pass seam uses.
#[derive(Debug)]
pub struct CommunityPassV1 {
    utc: TrustedUtcSecondV1,
    tick: u64,
    open: Arc<AtomicBool>,
}

impl CommunityPassV1 {
    /// An open pass at `utc` and `tick`, for tests (#584 adds the crate-internal constructor).
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn open_for_test(utc: TrustedUtcSecondV1, tick: u64) -> Self {
        Self {
            utc,
            tick,
            open: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Close the pass, for tests: every authorization of the pass reports it closed (#584 adds
    /// the crate-internal closer).
    #[cfg(any(test, feature = "test-support"))]
    pub fn close_for_test(&self) {
        self.open.store(false, Ordering::Release);
    }

    /// The trusted UTC second shared by every member of the pass.
    #[must_use]
    pub const fn utc(&self) -> TrustedUtcSecondV1 {
        self.utc
    }

    /// The Tick of the pass.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Whether the pass is still open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    /// The shared pass-open flag an authorization keeps.
    pub(super) fn open_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.open)
    }
}
