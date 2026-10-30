#![cfg(any(test, feature = "test-support"))]
//! Process-local admission selected by ADR-121, without a qualified store constructor.
//!
//! A trusted composition root must retain one shared `Arc<OwnerStoreAdmissionV1>`
//! for every supported owner/store view of the same bound context. Admission
//! precedes every lower lock and effect, including ordinary operations. A new
//! controller is for an unrelated context, never a way to recover a quarantined
//! binding. Binding, the complete handle inventory and native retirement remain
//! separate ADR-123 implementation requirements.

use std::sync::atomic::{AtomicU8, Ordering};

use pos_crypto::subject_field_read::SubjectFieldOwnerReadErrorV1;

const IDLE: u8 = 0;
const ACTIVE: u8 = 1;
const QUARANTINED: u8 = 2;

/// Nonblocking admission shared by all supported handles of one bound context.
///
/// This controller grants no key, consent, transaction or filesystem authority.
/// It has no reset or rebinding operation. A future bound root keeps it and its
/// operation guards private; exposing an ordinary adapter does not qualify it.
#[derive(Debug, Default)]
pub struct OwnerStoreAdmissionV1 {
    state: AtomicU8,
}

impl OwnerStoreAdmissionV1 {
    /// Create idle admission for a new, independently established context.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(IDLE),
        }
    }

    /// Attempt admission before acquiring any lower lock or invoking an effect.
    ///
    /// # Errors
    /// Returns `OperationActive` or `ContextQuarantined` without waiting or
    /// changing that state. Other supported ports must map these refusals to
    /// their own closed pre-effect errors.
    pub fn try_enter(&self) -> Result<OwnerStoreOperationV1<'_>, SubjectFieldOwnerReadErrorV1> {
        self.state
            .compare_exchange(IDLE, ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| OwnerStoreOperationV1 {
                admission: self,
                armed: true,
            })
            .map_err(|state| {
                if state == ACTIVE {
                    SubjectFieldOwnerReadErrorV1::OperationActive
                } else {
                    SubjectFieldOwnerReadErrorV1::ContextQuarantined
                }
            })
    }
}

/// One admitted operation; dropping it while armed permanently quarantines.
///
/// The guard cannot be cloned. Explicit quarantine must precede lower lock
/// release when transaction finish fails. Clean completion is permitted only
/// after positively proved closure, secret cleanup and release of lower locks.
#[derive(Debug)]
#[must_use = "an admitted operation must finish cleanly or quarantine its context"]
pub struct OwnerStoreOperationV1<'context> {
    admission: &'context OwnerStoreAdmissionV1,
    armed: bool,
}

impl OwnerStoreOperationV1<'_> {
    /// Restore idle admission after proved cleanup and released lower resources.
    ///
    /// # Panics
    /// An unexpected internal state is an invariant violation. The bound context
    /// must not be reused; an armed guard still defaults to quarantine on unwind.
    pub fn complete_cleanly(mut self) {
        self.transition(IDLE);
    }

    /// Permanently quarantine before releasing lower resources after failed finish.
    ///
    /// # Panics
    /// An unexpected internal state is an invariant violation. The bound context
    /// must not be reused.
    pub fn quarantine(mut self) {
        self.transition(QUARANTINED);
    }

    fn transition(&mut self, next: u8) {
        assert_eq!(
            self.admission.state.compare_exchange(
                ACTIVE,
                next,
                Ordering::AcqRel,
                Ordering::Acquire
            ),
            Ok(ACTIVE),
            "owner/store admission invariant violated"
        );
        self.armed = false;
    }
}

impl Drop for OwnerStoreOperationV1<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.transition(QUARANTINED);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn unexpected_transition_is_an_invariant_violation_and_does_not_reset_quarantine() {
        // Safe public operations cannot forge this state/token pair. Disarm the
        // synthetic token to inspect the assertion without a second drop panic.
        let admission = OwnerStoreAdmissionV1 {
            state: AtomicU8::new(QUARANTINED),
        };
        let operation = OwnerStoreOperationV1 {
            admission: &admission,
            armed: false,
        };
        assert!(std::panic::catch_unwind(|| operation.complete_cleanly()).is_err());
        assert_eq!(
            admission.try_enter().err(),
            Some(SubjectFieldOwnerReadErrorV1::ContextQuarantined)
        );
    }
}
