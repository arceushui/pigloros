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

#[cfg(test)]
fn ticket_turn(
    ticket: &Result<Ticket<'_>, Box<dyn std::error::Error>>,
    now: Instant,
) -> Result<bool, String> {
    ticket
        .as_ref()
        .map_err(ToString::to_string)
        .and_then(|ticket| ticket.is_next(now).map_err(|error| error.to_string()))
}

#[test]
fn waiting_cases_keep_their_turn_when_a_hot_worker_returns_or_a_waiter_cancels() {
    let foreground = Foreground::default();
    let now = Instant::now();
    let first = foreground.request(1, now);
    assert!(first.is_ok(), "request failed: {:?}", first.as_ref().err());
    let cancelled = foreground.request(2, now);
    assert!(
        cancelled.is_ok(),
        "request failed: {:?}",
        cancelled.as_ref().err()
    );
    let waiting = foreground.request(3, now);
    assert!(
        waiting.is_ok(),
        "request failed: {:?}",
        waiting.as_ref().err()
    );
    assert_eq!(ticket_turn(&first, now), Ok(true));
    assert_eq!(ticket_turn(&waiting, now), Ok(false));
    drop(cancelled);
    drop(first);
    let returning = foreground.request(4, now);
    assert_eq!(ticket_turn(&returning, now), Ok(false));
    assert_eq!(ticket_turn(&waiting, now), Ok(true));
    drop(waiting);
    assert_eq!(ticket_turn(&returning, now), Ok(true));
    drop(returning);
    assert_eq!(ticket_turn(&foreground.request(5, now), now), Ok(true));
}

#[test]
fn poisoned_foreground_coordination_refuses_new_and_waiting_cases() {
    let foreground = Foreground::default();
    let now = Instant::now();
    let waiting = foreground.request(1, now);
    assert!(
        waiting.is_ok(),
        "request failed: {:?}",
        waiting.as_ref().err()
    );
    // Narrow fault injection: no page/input code executes under this lock.
    // A harness unwind must refuse focus rather than admit competing cases.
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _locked = foreground.0.lock();
        std::panic::resume_unwind(Box::new("controlled foreground lock poison"));
    }));
    assert!(poisoned.is_err());
    assert_eq!(
        ticket_turn(&waiting, now),
        Err("foreground queue poisoned".into())
    );
    assert_eq!(
        ticket_turn(&foreground.request(2, now), now),
        Err("foreground queue poisoned".into())
    );
    drop(waiting);
}

#[test]
fn expired_unstarted_cases_refuse_admission_and_release_their_place() {
    let foreground = Foreground::default();
    let start = Instant::now();
    let active = foreground.request(1, start);
    assert!(
        active.is_ok(),
        "request failed: {:?}",
        active.as_ref().err()
    );
    let expired = foreground.request(2, start);
    assert!(
        expired.is_ok(),
        "request failed: {:?}",
        expired.as_ref().err()
    );
    let limit = start + Duration::from_mins(2);
    assert_eq!(
        ticket_turn(&expired, start + Duration::from_millis(119_999)),
        Ok(false)
    );
    assert_eq!(
        ticket_turn(&expired, limit),
        Err("native fixture desktop admission timed out before plan creation".into())
    );
    drop(active);
    // Becoming first after the ceiling does not restart its admission budget.
    assert_eq!(
        ticket_turn(&expired, limit),
        Err("native fixture desktop admission timed out before plan creation".into())
    );
    drop(expired);
    let fresh = foreground.request(3, limit);
    assert_eq!(ticket_turn(&fresh, limit), Ok(true));
}
