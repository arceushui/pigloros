#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::Mutex;

/// Unique fixture case numbers wait in arrival order. The queue lock is never
/// held across COM; its front ticket retains foreground ownership until receipt
/// or cancellation. A hot worker cannot bypass an older waiting case.
#[derive(Default)]
pub(super) struct Foreground(Mutex<VecDeque<u64>>);

pub(super) struct Ticket<'a> {
    foreground: &'a Foreground,
    case: u64,
}

impl Foreground {
    pub(super) fn request(&self, case: u64) -> Result<Ticket<'_>, Box<dyn std::error::Error>> {
        self.0
            .lock()
            .map_err(|_| "foreground queue poisoned")?
            .push_back(case);
        Ok(Ticket {
            foreground: self,
            case,
        })
    }
}

impl Ticket<'_> {
    pub(super) fn is_next(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(self
            .foreground
            .0
            .lock()
            .map_err(|_| "foreground queue poisoned")?
            .front()
            == Some(&self.case))
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if let Ok(mut waiting) = self.foreground.0.lock() {
            waiting.retain(|case| *case != self.case);
        }
    }
}

#[test]
fn waiting_cases_keep_their_turn_when_a_hot_worker_returns_or_a_waiter_cancels(
) -> Result<(), Box<dyn std::error::Error>> {
    let foreground = Foreground::default();
    let first = foreground.request(1)?;
    let cancelled = foreground.request(2)?;
    let waiting = foreground.request(3)?;
    assert!(first.is_next()?);
    assert!(!waiting.is_next()?);
    drop(cancelled);
    drop(first);
    let returning = foreground.request(4)?;
    assert!(!returning.is_next()?);
    assert!(waiting.is_next()?);
    drop(waiting);
    assert!(returning.is_next()?);
    drop(returning);
    assert!(foreground.request(5)?.is_next()?);
    Ok(())
}

#[test]
fn poisoned_foreground_coordination_refuses_new_and_waiting_cases(
) -> Result<(), Box<dyn std::error::Error>> {
    let foreground = Foreground::default();
    let waiting = foreground.request(1)?;
    // Narrow fault injection: no page/input code executes under this lock.
    // A harness unwind must refuse focus rather than admit competing cases.
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _locked = foreground.0.lock();
        std::panic::resume_unwind(Box::new("controlled foreground lock poison"));
    }));
    assert!(poisoned.is_err());
    assert!(waiting.is_next().is_err());
    assert!(foreground.request(2).is_err());
    drop(waiting);
    Ok(())
}
