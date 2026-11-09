#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write as _;

use crate::NativeResult;

// Temporary hosted-hang probe. Logarithmic sampling bounds retry output without
// adding a clock, deadline, cleanup action or permission to release an owner.
#[derive(Default)]
pub(super) struct CleanupTrace(RefCell<BTreeMap<&'static str, Step>>);

#[derive(Default)]
struct Step {
    attempts: u64,
    result: Option<NativeResult<()>>,
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
        if step.attempts.is_power_of_two() || step.result != Some(result) {
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_CLEANUP_PROBE stage={stage} attempt={} result={result:?}",
                step.attempts,
            );
        }
        step.result = Some(result);
    }
}
