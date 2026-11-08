#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// A separate harness ceiling before any ceremony plan/T0 exists. This is not
// a product readiness allowance and cannot extend an already-created plan.
const SLOT_WAIT: Duration = Duration::from_mins(2);

/// Unique fixture case numbers wait in arrival order. The queue lock is never
/// held across COM; its front ticket retains ownership through cancellation and
/// actual retirement. A hot worker cannot bypass an older waiting case.
#[derive(Default)]
pub(super) struct Foreground(Mutex<VecDeque<u64>>);

pub(super) struct Ticket<'a> {
    foreground: &'a Foreground,
    case: u64,
    deadline: Instant,
}

impl Foreground {
    pub(super) fn request(
        &self,
        case: u64,
        now: Instant,
    ) -> Result<Ticket<'_>, Box<dyn std::error::Error>> {
        self.0
            .lock()
            .map_err(|_| "foreground queue poisoned")?
            .push_back(case);
        Ok(Ticket {
            foreground: self,
            case,
            deadline: now + SLOT_WAIT,
        })
    }
}

impl Ticket<'_> {
    pub(super) fn is_next(&self, now: Instant) -> Result<bool, Box<dyn std::error::Error>> {
        if now >= self.deadline {
            return Err("native fixture desktop admission timed out before plan creation".into());
        }
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
    let now = Instant::now();
    let first = foreground.request(1, now)?;
    let cancelled = foreground.request(2, now)?;
    let waiting = foreground.request(3, now)?;
    assert!(first.is_next(now)?);
    assert!(!waiting.is_next(now)?);
    drop(cancelled);
    drop(first);
    let returning = foreground.request(4, now)?;
    assert!(!returning.is_next(now)?);
    assert!(waiting.is_next(now)?);
    drop(waiting);
    assert!(returning.is_next(now)?);
    drop(returning);
    assert!(foreground.request(5, now)?.is_next(now)?);
    Ok(())
}

#[test]
fn poisoned_foreground_coordination_refuses_new_and_waiting_cases(
) -> Result<(), Box<dyn std::error::Error>> {
    let foreground = Foreground::default();
    let now = Instant::now();
    let waiting = foreground.request(1, now)?;
    // Narrow fault injection: no page/input code executes under this lock.
    // A harness unwind must refuse focus rather than admit competing cases.
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _locked = foreground.0.lock();
        std::panic::resume_unwind(Box::new("controlled foreground lock poison"));
    }));
    assert!(poisoned.is_err());
    assert!(waiting.is_next(now).is_err());
    assert!(foreground.request(2, now).is_err());
    drop(waiting);
    Ok(())
}

#[test]
fn expired_unstarted_cases_refuse_admission_and_release_their_place(
) -> Result<(), Box<dyn std::error::Error>> {
    let foreground = Foreground::default();
    let start = Instant::now();
    let active = foreground.request(1, start)?;
    let expired = foreground.request(2, start)?;
    let limit = start + Duration::from_mins(2);
    assert!(!expired.is_next(start + Duration::from_millis(119_999))?);
    assert!(expired.is_next(limit).is_err());
    drop(active);
    // Becoming first after the ceiling does not restart its admission budget.
    assert!(expired.is_next(limit).is_err());
    drop(expired);
    let fresh = foreground.request(3, limit)?;
    assert!(fresh.is_next(limit)?);
    Ok(())
}
