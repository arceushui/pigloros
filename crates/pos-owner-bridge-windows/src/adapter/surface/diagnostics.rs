#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write as _;

use crate::NativeResult;

use super::{CloseState, Ownership, Surface};
use std::rc::Rc;

impl Surface {
    #[cfg(test)]
    pub(in crate::adapter) fn quarantined_fault_state(
        &mut self,
    ) -> Result<crate::ProcessExitState, ()> {
        if self.ownership != Ownership::Controller
            || self.close != CloseState::Idle
            || self.failed_open
            || self.events.invalid()
            || self.events.exited().is_some()
            || self.buffers
            || !self.navigation_issued
            || self.events.loaded().is_none()
            || self.loopback.served().count != 1
            || !self.loopback.served().integrity_ok
            || !crate::Native::process_failure_observations().is_empty()
            || self.native.buffer_close_uncertain()
            || !self.native.preload_fault_owners_retained()
            || !self.native.window().map_err(|_| ())?.exists
            || self.native.early_renderer_presence()? != crate::RendererPresence::Unique
        {
            return Err(());
        }
        let browser = self.identity.ok_or(())?;
        self.verify_fault_environment()?;
        self.verify_fault_identity(browser)?;
        let state = crate::ProcessExitState {
            generation: self.generation.ok_or(())?,
            record_count: self.store.records().map_err(|_| ())?.len(),
        };
        if state.generation != 1 || state.record_count != 1 {
            return Err(());
        }
        Ok(state)
    }

    #[cfg(test)]
    pub(in crate::adapter) fn inject_quarantined_fault(
        &mut self,
        target: crate::ProcessFaultTarget,
        seal: crate::FaultSeal,
        keeper_held: Rc<Cell<bool>>,
    ) -> Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        if !keeper_held.get() {
            return Err(());
        }
        self.quarantined_fault_state()?;
        let browser = self.identity.ok_or(())?;
        let events = Rc::clone(&self.events);
        let (trace, deadline) = seal.into_parts();
        let authority = crate::FaultAuthority {
            browser,
            target,
            lifecycle: crate::ProcessFaultLifecycle::Quarantined,
            valid: Rc::new(move || {
                std::time::Instant::now() < deadline
                    && keeper_held.get()
                    && !events.invalid()
                    && events.exited().is_none()
            }),
            trace,
        };
        self.native.inject_process_fault(&authority)
    }
}

// Temporary hosted-hang probe. Logarithmic sampling bounds retry output without
// adding a clock, deadline, cleanup action or permission to release an owner.
#[derive(Default)]
pub(super) struct CleanupTrace(RefCell<BTreeMap<&'static str, Step>>);

#[derive(Default)]
struct Step {
    attempts: u64,
    result: Option<NativeResult<()>>,
    transitions: u8,
}

impl CleanupTrace {
    pub(super) fn enter(&self, stage: &'static str) {
        let mut steps = self.0.borrow_mut();
        let step = steps.entry(stage).or_default();
        step.attempts = step.attempts.saturating_add(1);
        if step.attempts.is_power_of_two() {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_CLEANUP_PROBE stage={stage} attempt={} entered=true",
                step.attempts,
            );
        }
        // No RefCell borrow survives the following native call or its callbacks.
    }

    pub(super) fn returned(&self, stage: &'static str, result: NativeResult<()>) {
        let mut steps = self.0.borrow_mut();
        let step = steps.entry(stage).or_default();
        let report_transition = step.result != Some(result) && step.transitions < 8;
        if report_transition {
            step.transitions += 1;
        }
        if step.attempts.is_power_of_two() || report_transition {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_CLEANUP_PROBE stage={stage} attempt={} result={result:?}",
                step.attempts,
            );
        }
        step.result = Some(result);
    }
}

/// One readiness case's host-side transitions; each instant is recorded at most once.
#[derive(Default)]
pub(super) struct ReadinessTiming {
    case: Option<u64>,
    started: Option<std::time::Instant>,
    cas: std::cell::Cell<Option<std::time::Instant>>,
    releasing: std::cell::Cell<Option<std::time::Instant>>,
    close_enter: std::cell::Cell<Option<std::time::Instant>>,
    close_return: std::cell::Cell<Option<std::time::Instant>>,
}

impl ReadinessTiming {
    pub(super) fn begin(&mut self, case: u64, started: std::time::Instant) {
        *self = Self {
            case: Some(case),
            started: Some(started),
            ..Self::default()
        };
    }

    fn mark(&self, slot: &std::cell::Cell<Option<std::time::Instant>>) {
        if self.case.is_some() && slot.get().is_none() {
            slot.set(Some(std::time::Instant::now()));
        }
    }

    pub(super) fn cas(&self) {
        self.mark(&self.cas);
    }
    pub(super) fn releasing(&self) {
        self.mark(&self.releasing);
    }
    pub(super) fn close_enter(&self) {
        self.mark(&self.close_enter);
    }
    pub(super) fn close_return(&self) {
        self.mark(&self.close_return);
    }

    pub(super) fn report(&mut self) {
        if let (Some(case), Some(started)) = (self.case, self.started) {
            let elapsed = |slot: &std::cell::Cell<Option<std::time::Instant>>| {
                slot.get().map(|at| at.saturating_duration_since(started))
            };
            let _logged_or_unavailable = writeln!(std::io::stderr(),
                "NATIVE_READINESS_TIMING case={case} release_cas={:?} releasing={:?} close_enter={:?} native_close_return={:?}",
                elapsed(&self.cas), elapsed(&self.releasing), elapsed(&self.close_enter), elapsed(&self.close_return));
        }
        *self = Self::default();
    }
}
