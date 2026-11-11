#![cfg(windows)]
#![forbid(unsafe_code)]

use super::{spec, Creation, Fixture, Surface, TestResult};
use crate::{ProcessFaultTarget, RetryPoint};

fn assert_no_fault_boundary(surface: &mut Surface) {
    assert!(surface.pre_environment_completion().is_err());
    assert!(!surface.recordless_opening_ready());
    assert!(surface.recordless_controller_completion().is_none());
    assert!(surface.prepare_recordless_browser().is_err());
    assert!(surface.prepare_pending_opening_browser().is_err());
    assert!(surface.before_record_fault_state().is_err());
    assert!(surface.navigating_fault_state(1, 0).is_err());
    assert!(surface.awaiting_load_fault_state(1, 0).is_err());
    assert!(surface.posted_fault_state(1).is_err());
    assert!(surface.posted_empty_fault_state(1).is_err());
    assert!(surface.posted_writing_fault_state(1).is_err());
    assert!(surface.posted_ready_fault_state(1).is_err());
    assert!(surface
        .posted_retry_fault_state(2, RetryPoint::Second)
        .is_err());
    assert!(surface.releasing_fault_state(1).is_err());
    assert!(!surface.before_record_owners_retained());
    assert!(!surface.recordless_fault_owners_retained());
    assert!(!surface.pending_opening_owners_retained());
    assert!(!surface.fault_owners_retained());
    assert!(!surface.exit_fault_phase_reached());
    assert!(!surface.exit_fault_owners_retained());
}

#[test]
fn idle_surface_exposes_no_fault_boundary_or_browser_event() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let calls = fixture.factory.calls.borrow().clone();
    assert_no_fault_boundary(&mut fixture.surface);
    assert!(fixture
        .surface
        .pre_environment_retention(&spec(40).ceremony_id)
        .is_none());
    assert!(fixture.surface.recordless_fault_event().is_err());
    assert!(fixture
        .surface
        .posted_fault_event(ProcessFaultTarget::Browser)
        .is_err());
    assert_eq!(*fixture.factory.calls.borrow(), calls);
    assert!(fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    Ok(())
}

#[test]
fn navigated_surface_without_buffers_exposes_no_fault_boundary() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    let calls = fixture.factory.calls.borrow().clone();
    assert_no_fault_boundary(&mut fixture.surface);
    assert!(matches!(
        fixture
            .surface
            .posted_fault_event(ProcessFaultTarget::Browser),
        Ok(None)
    ));
    assert_eq!(*fixture.factory.calls.borrow(), calls);
    assert!(fixture.store.records_now().is_empty());
    fixture.finish()
}
