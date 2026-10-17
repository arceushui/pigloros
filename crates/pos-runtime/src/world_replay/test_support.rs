//! Nonproduction observations of the protected Replay lifecycle.
//!
//! Observers receive only phase identities, never authority, Store access,
//! State, a sender or the operation ledger. Each scope is thread-local and
//! restores its previous observer on both return and unwind.

use pos_core::TimelineId;
use std::{cell::RefCell, rc::Rc};

/// Actual lifecycle boundaries used by complete public-consumer tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayPhaseV1 {
    /// Entered the actual concrete containment fence for this ancestor.
    GateEntered(TimelineId),
    /// Leaving that concrete fence, including during unwind.
    GateLeaving(TimelineId),
    /// Detached preparation returned successfully, before the final check.
    Staged,
    /// Final original-g0 check passed; Time has not installed State yet.
    BeforeComplete,
    /// Time successfully installed its State or pair; native rollback is next.
    Installed,
    /// About to settle an owned native interval.
    BeforeRollback,
    /// Native settlement returned, including a closed cleanup error.
    AfterRollback,
    /// Time measured failure-path release health.
    FailureP2,
    /// Time invoked failure-path revoked-subject forgetting.
    FailureForget,
}

type Observer = Rc<dyn Fn(ReplayPhaseV1)>;

thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

struct RestoreObserver(Option<Observer>);

impl Drop for RestoreObserver {
    fn drop(&mut self) {
        OBSERVER.with(|slot| slot.replace(self.0.take()));
    }
}

/// Observe one synchronous test operation, restoring any enclosing observer.
pub fn with_replay_observer<T>(observer: Observer, operation: impl FnOnce() -> T) -> T {
    let _restore = RestoreObserver(OBSERVER.with(|slot| slot.replace(Some(observer))));
    operation()
}

/// Record a phase from a test-enabled Runtime or its Time consumer.
pub fn record_replay_phase(phase: ReplayPhaseV1) {
    let observer = OBSERVER.with(|slot| slot.borrow().clone());
    if let Some(observer) = observer {
        observer(phase);
    }
}

pub(crate) struct ObservedGateV1(TimelineId);

impl ObservedGateV1 {
    pub(crate) fn enter(timeline: TimelineId) -> Self {
        record_replay_phase(ReplayPhaseV1::GateEntered(timeline));
        Self(timeline)
    }
}

impl Drop for ObservedGateV1 {
    fn drop(&mut self) {
        record_replay_phase(ReplayPhaseV1::GateLeaving(self.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_observers_restore_on_return_and_unwind_and_gates_leave_on_unwind() {
        let outer = Rc::new(RefCell::new(Vec::new()));
        let inner = Rc::new(RefCell::new(Vec::new()));
        let timeline = TimelineId::new();
        with_replay_observer(
            Rc::new({
                let outer = Rc::clone(&outer);
                move |phase| outer.borrow_mut().push(phase)
            }),
            || {
                record_replay_phase(ReplayPhaseV1::Staged);
                with_replay_observer(
                    Rc::new({
                        let inner = Rc::clone(&inner);
                        move |phase| inner.borrow_mut().push(phase)
                    }),
                    || record_replay_phase(ReplayPhaseV1::BeforeComplete),
                );
                record_replay_phase(ReplayPhaseV1::Installed);
                let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    with_replay_observer(
                        Rc::new({
                            let inner = Rc::clone(&inner);
                            move |phase| inner.borrow_mut().push(phase)
                        }),
                        || {
                            let _gate = ObservedGateV1::enter(timeline);
                            std::panic::resume_unwind(Box::new("observer unwind control"));
                        },
                    );
                }));
                assert!(unwind.is_err());
                record_replay_phase(ReplayPhaseV1::AfterRollback);
            },
        );
        record_replay_phase(ReplayPhaseV1::FailureP2);
        assert_eq!(
            *outer.borrow(),
            [
                ReplayPhaseV1::Staged,
                ReplayPhaseV1::Installed,
                ReplayPhaseV1::AfterRollback
            ]
        );
        assert_eq!(
            *inner.borrow(),
            [
                ReplayPhaseV1::BeforeComplete,
                ReplayPhaseV1::GateEntered(timeline),
                ReplayPhaseV1::GateLeaving(timeline)
            ]
        );
    }
}
