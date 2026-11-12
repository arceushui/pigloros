#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::host::StoreOp;
use pos_owner_bridge::{
    BridgeError, CleanupStore, OwnerWebSurface, ProcessIdentity, UnavailableCode,
};

use super::fault_states::{change_identity, finish_posted, posted_fixture};
use super::{spec, Creation, Fixture, Runtime, RuntimeAdmission, Surface, TestResult};
use crate::{EventSink, FaultSeal, NativeEvent, ProcessFaultMark, ProcessFaultTarget, RetryPoint};
use pos_owner_bridge_codec::ControlState;

fn pending_fixture() -> Result<(Fixture, ProcessIdentity), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let selected = spec(121);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    let browser = fixture.surface.runtime.identity(42)?;
    fixture.factory.pending_browser.set(Some(browser));
    Ok((fixture, browser))
}

fn retire_pending(fixture: &mut Fixture) -> TestResult {
    fixture.factory.failure.set(None);
    fixture.store.set_failing(&[]);
    fixture.surface.abandon_opening();
    fixture.factory.creation.set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    Ok(())
}

fn seal() -> FaultSeal {
    FaultSeal {
        trace: Rc::default(),
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

#[test]
fn pending_fault_admission_binds_the_candidate_and_retains_its_owners() -> TestResult {
    let (mut fixture, browser) = pending_fixture()?;
    assert!(!fixture.surface.pending_opening_owners_retained());
    assert_eq!(
        fixture.surface.prepare_pending_opening_browser(),
        Ok(Some(browser))
    );
    assert!(fixture.surface.pending_opening_owners_retained());
    assert_eq!(fixture.surface.recordless_fault_event(), Ok(None));
    // The incomplete modeled native session inherits the fail-closed injector.
    // Admission cannot turn that session into a native process-fault provider.
    assert!(fixture
        .surface
        .inject_pending_opening_browser(seal())
        .is_err());
    assert!(fixture.surface.pending_opening_owners_retained());
    fixture.exit();
    assert_eq!(
        fixture.surface.recordless_fault_event(),
        Ok(Some(ProcessFaultMark::OwnBrowserExited))
    );
    assert!(fixture
        .surface
        .inject_pending_opening_browser(seal())
        .is_err());
    retire_pending(&mut fixture)
}

#[test]
fn pending_fault_admission_rejects_lost_ownership_and_candidate_failures() -> TestResult {
    for failure in [
        "pending-owner",
        "pending_candidate",
        "pending-callback-after",
        "environment",
    ] {
        let (mut fixture, _) = pending_fixture()?;
        fixture.factory.failure.set(Some(failure));
        assert!(
            fixture.surface.prepare_pending_opening_browser().is_err(),
            "accepted {failure}"
        );
        assert!(!fixture.surface.pending_opening_owners_retained());
        assert!(fixture
            .surface
            .inject_pending_opening_browser(seal())
            .is_err());
        fixture.assert_no_ceremony_data();
        retire_pending(&mut fixture)?;
    }
    let (mut fixture, _) = pending_fixture()?;
    fixture.factory.failure.set(Some("pending-callback-after"));
    fixture
        .surface
        .native
        .pending_opening_browser_candidate()
        .map_err(|()| "modeled candidate")?;
    assert!(fixture.surface.prepare_pending_opening_browser().is_err());
    retire_pending(&mut fixture)
}

#[test]
fn pending_fault_admission_rejects_invalid_events_and_unreadable_records() -> TestResult {
    for event in [
        NativeEvent::NewWindow,
        NativeEvent::BrowserExited { pid: 43 },
    ] {
        let (mut fixture, _) = pending_fixture()?;
        let _action = fixture.surface.events.event(event);
        assert!(fixture.surface.prepare_pending_opening_browser().is_err());
        assert!(fixture.surface.recordless_fault_event().is_err());
        assert!(!fixture.surface.pending_opening_owners_retained());
        retire_pending(&mut fixture)?;
    }
    let (mut fixture, _) = pending_fixture()?;
    fixture.store.set_failing(&[StoreOp::List]);
    assert!(fixture.surface.prepare_pending_opening_browser().is_err());
    fixture.store.set_failing(&[]);
    fixture.store.preload(vec![0x80]);
    assert!(fixture.surface.prepare_pending_opening_browser().is_err());
    assert!(!fixture.surface.pending_opening_owners_retained());
    fixture
        .store
        .delete_record(&[0x80])
        .map_err(|_| "restore modeled store")?;
    retire_pending(&mut fixture)
}

struct UnavailableIdentity;

impl RuntimeAdmission for UnavailableIdentity {
    fn root(&self) -> &Path {
        Path::new("")
    }

    fn identity(&self, _: u32) -> Result<ProcessIdentity, BridgeError> {
        Err(BridgeError::Unavailable(UnavailableCode::RuntimeIntegrity))
    }
}

#[test]
fn pending_fault_admission_rejects_changed_or_unavailable_process_identity() -> TestResult {
    let (mut fixture, mut browser) = pending_fixture()?;
    browser.creation_filetime += 1;
    fixture.factory.pending_browser.set(Some(browser));
    assert!(fixture.surface.prepare_pending_opening_browser().is_err());
    assert!(!fixture.surface.pending_opening_owners_retained());
    retire_pending(&mut fixture)?;

    let (mut fixture, _) = pending_fixture()?;
    fixture.surface.runtime = Arc::new(UnavailableIdentity);
    assert!(fixture.surface.prepare_pending_opening_browser().is_err());
    assert!(!fixture.surface.pending_opening_owners_retained());
    retire_pending(&mut fixture)
}

struct ChangedIdentity {
    root: std::path::PathBuf,
    browser: ProcessIdentity,
}

impl RuntimeAdmission for ChangedIdentity {
    fn root(&self) -> &Path {
        &self.root
    }

    fn identity(&self, _: u32) -> Result<ProcessIdentity, BridgeError> {
        Ok(self.browser)
    }
}

#[derive(Clone, Copy)]
enum IdentityChange {
    Candidate,
    Runtime,
    Unavailable,
}

fn fault_attempts(fixture: &Fixture) -> Vec<&'static str> {
    fixture
        .factory
        .calls
        .borrow()
        .iter()
        .copied()
        .filter(|call| call.starts_with("fault_"))
        .collect()
}

#[test]
fn modeled_pending_fault_rechecks_identity_after_selection() -> TestResult {
    for change in [
        IdentityChange::Candidate,
        IdentityChange::Runtime,
        IdentityChange::Unavailable,
    ] {
        let (mut fixture, browser) = pending_fixture()?;
        assert_eq!(
            fixture.surface.prepare_pending_opening_browser(),
            Ok(Some(browser))
        );
        fixture.factory.failure.set(Some("fault_spy"));
        // The modeled port observes admission, but always refuses and never
        // creates a handle or terminates a process.
        assert!(fixture
            .surface
            .inject_pending_opening_browser(seal())
            .is_err());
        assert_eq!(fault_attempts(&fixture), ["fault_valid"]);
        let original_runtime = Arc::clone(&fixture.surface.runtime);
        let mut changed = browser;
        changed.creation_filetime += 1;
        match change {
            IdentityChange::Candidate => fixture.factory.pending_browser.set(Some(changed)),
            IdentityChange::Runtime => {
                fixture.surface.runtime = Arc::new(ChangedIdentity {
                    root: fixture.root.clone(),
                    browser: changed,
                });
            }
            IdentityChange::Unavailable => fixture.surface.runtime = Arc::new(UnavailableIdentity),
        }
        assert!(fixture
            .surface
            .inject_pending_opening_browser(seal())
            .is_err());
        assert_eq!(fault_attempts(&fixture), ["fault_valid"]);
        assert!(!fixture.surface.idle());
        fixture.assert_no_ceremony_data();
        fixture.surface.runtime = original_runtime;
        retire_pending(&mut fixture)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_fault_validity_rechecks_events_at_the_native_port() -> TestResult {
    for (mode, observed) in [
        ("fault_spy", "fault_valid"),
        ("fault_spy_frame", "fault_invalid"),
        ("fault_spy_exit", "fault_invalid"),
    ] {
        let (mut fixture, browser) = pending_fixture()?;
        assert_eq!(
            fixture.surface.prepare_pending_opening_browser(),
            Ok(Some(browser))
        );
        fixture.factory.failure.set(Some(mode));
        assert!(fixture
            .surface
            .inject_pending_opening_browser(seal())
            .is_err());
        assert_eq!(fault_attempts(&fixture), [observed]);
        assert!(!fixture.surface.idle());
        fixture.assert_no_ceremony_data();
        retire_pending(&mut fixture)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_fault_expiry_is_observed_without_a_fault_handle() -> TestResult {
    let (mut fixture, browser) = pending_fixture()?;
    assert_eq!(
        fixture.surface.prepare_pending_opening_browser(),
        Ok(Some(browser))
    );
    fixture.factory.failure.set(Some("fault_spy"));
    let mut expired = seal();
    expired.deadline = Instant::now();
    assert!(fixture
        .surface
        .inject_pending_opening_browser(expired)
        .is_err());
    assert_eq!(fault_attempts(&fixture), ["fault_invalid"]);
    assert!(fixture.surface.pending_opening_owners_retained());
    fixture.assert_no_ceremony_data();
    retire_pending(&mut fixture)
}

#[derive(Clone, Copy)]
enum PostedInjection {
    Receipt,
    Empty,
    Writing,
    Ready,
    Retry,
    Consuming,
    Releasing,
}

impl PostedInjection {
    fn state(self) -> ControlState {
        match self {
            Self::Receipt => ControlState::Received,
            Self::Empty | Self::Retry => ControlState::Empty,
            Self::Writing => ControlState::Writing,
            Self::Ready => ControlState::Ready,
            Self::Consuming => ControlState::Consuming,
            Self::Releasing => ControlState::ReleaseRequested,
        }
    }

    fn generation(self) -> u32 {
        if matches!(self, Self::Retry) {
            2
        } else {
            1
        }
    }

    fn invoke(
        self,
        surface: &Surface,
        deadline: std::time::Instant,
    ) -> Result<Box<dyn crate::ProcessFaultHandle>, ()> {
        let seal = crate::FaultSeal {
            trace: std::rc::Rc::default(),
            deadline,
        };
        let target = ProcessFaultTarget::Browser;
        match self {
            Self::Receipt => surface.inject_posted_fault(target, seal),
            Self::Empty => surface.inject_posted_empty_fault(target, seal),
            Self::Writing => surface.inject_posted_writing_fault(target, seal),
            Self::Ready => surface.inject_posted_ready_fault(target, seal),
            Self::Retry => surface.inject_posted_retry_fault(target, RetryPoint::Second, seal),
            Self::Consuming => surface.inject_posted_consuming_fault(target, seal),
            Self::Releasing => surface.inject_releasing_fault(target, seal),
        }
    }
}

fn spy_calls(fixture: &Fixture) -> Vec<&'static str> {
    fixture
        .factory
        .calls
        .borrow()
        .iter()
        .copied()
        .filter(|call| matches!(*call, "fault_valid" | "fault_invalid"))
        .collect()
}

#[test]
fn modeled_posted_injections_validate_state_generation_identity_and_seal() -> TestResult {
    for point in [
        PostedInjection::Receipt,
        PostedInjection::Empty,
        PostedInjection::Writing,
        PostedInjection::Ready,
        PostedInjection::Retry,
        PostedInjection::Consuming,
        PostedInjection::Releasing,
    ] {
        let mut fixture = posted_fixture(point.generation())?;
        fixture.factory.state.set(point.state() as u32);
        let future = || std::time::Instant::now() + std::time::Duration::from_secs(10);
        assert!(point.invoke(&fixture.surface, future()).is_err());
        assert_eq!(spy_calls(&fixture), ["fault_valid"]);
        assert!(point
            .invoke(&fixture.surface, std::time::Instant::now())
            .is_err());
        assert_eq!(spy_calls(&fixture), ["fault_valid", "fault_invalid"]);
        for wrong in [
            u32::MAX,
            if point.state() == ControlState::Ready {
                ControlState::Empty as u32
            } else {
                ControlState::Ready as u32
            },
        ] {
            fixture.factory.state.set(wrong);
            assert!(point.invoke(&fixture.surface, future()).is_err());
            assert_eq!(spy_calls(&fixture), ["fault_valid", "fault_invalid"]);
        }
        fixture.factory.state.set(point.state() as u32);
        change_identity(&mut fixture, 0);
        assert!(point.invoke(&fixture.surface, future()).is_err());
        assert_eq!(spy_calls(&fixture), ["fault_valid", "fault_invalid"]);
        assert_eq!(fixture.store.records_now(), [vec![0x80]]);
        assert!(!fixture.surface.idle());
        fixture.surface.runtime = Arc::new(Runtime(fixture.root.clone()));
        finish_posted(fixture)?;

        let wrong_generation = if point.generation() == 1 { 2 } else { 1 };
        let fixture = posted_fixture(wrong_generation)?;
        fixture.factory.state.set(point.state() as u32);
        assert!(point.invoke(&fixture.surface, future()).is_err());
        assert!(spy_calls(&fixture).is_empty());
        assert_eq!(fixture.store.records_now(), [vec![0x80]]);
        assert!(!fixture.surface.idle());
        finish_posted(fixture)?;
    }
    Ok(())
}

#[test]
fn pending_fault_admission_rejects_a_missing_or_displaced_folder() -> TestResult {
    let (mut fixture, browser) = pending_fixture()?;
    let folder = fixture
        .surface
        .folder
        .take()
        .ok_or("missing modeled folder")?;
    assert_eq!(fixture.surface.prepare_pending_opening_browser(), Err(()));
    let path = fixture.root.join(&folder);
    fixture.surface.folder = Some(folder);
    let displaced = fixture.root.join("displaced-pending-opening-folder");
    std::fs::rename(&path, &displaced)?;
    assert_eq!(fixture.surface.prepare_pending_opening_browser(), Err(()));
    assert!(!fixture.surface.pending_opening_owners_retained());
    std::fs::rename(&displaced, &path)?;
    assert_eq!(
        fixture.surface.prepare_pending_opening_browser(),
        Ok(Some(browser))
    );
    fixture.assert_no_ceremony_data();
    retire_pending(&mut fixture)
}

#[test]
fn fault_events_refuse_an_exit_from_another_browser() -> TestResult {
    let (mut fixture, browser) = pending_fixture()?;
    let _action = fixture
        .surface
        .events
        .event(NativeEvent::BrowserExited { pid: 43 });
    fixture.surface.recordless_fault = Some(browser);
    assert_eq!(fixture.surface.recordless_fault_event(), Err(()));
    fixture.surface.recordless_fault = None;
    fixture.surface.identity = Some(browser);
    assert_eq!(
        fixture
            .surface
            .posted_fault_event(ProcessFaultTarget::Browser),
        Err(())
    );
    fixture.surface.identity = None;
    fixture.assert_no_ceremony_data();
    retire_pending(&mut fixture)
}

#[test]
fn modeled_posted_injections_refuse_an_unreadable_reply_state() -> TestResult {
    for point in [
        PostedInjection::Receipt,
        PostedInjection::Empty,
        PostedInjection::Writing,
        PostedInjection::Ready,
        PostedInjection::Retry,
        PostedInjection::Consuming,
        PostedInjection::Releasing,
    ] {
        let fixture = posted_fixture(point.generation())?;
        fixture.factory.state.set(point.state() as u32);
        fixture.factory.failure.set(Some("load_state"));
        assert!(point
            .invoke(&fixture.surface, Instant::now() + Duration::from_secs(10))
            .is_err());
        assert!(spy_calls(&fixture).is_empty());
        assert_eq!(fixture.store.records_now(), [vec![0x80]]);
        assert!(!fixture.surface.idle());
        finish_posted(fixture)?;
    }
    Ok(())
}

#[test]
fn idle_surface_refuses_every_fault_injection_exit_capture_and_finish() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let before = fixture.factory.calls.borrow().clone();
    let target = ProcessFaultTarget::Browser;
    assert!(fixture.surface.inject_recordless_browser(seal()).is_err());
    assert!(fixture
        .surface
        .inject_awaiting_load_fault(target, seal())
        .is_err());
    assert!(fixture
        .surface
        .inject_navigating_fault(target, seal())
        .is_err());
    assert!(fixture
        .surface
        .inject_before_record_fault(target, seal())
        .is_err());
    assert!(fixture
        .surface
        .inject_quarantined_fault(target, seal(), Rc::new(std::cell::Cell::new(true)))
        .is_err());
    assert!(fixture
        .surface
        .consume_exit_capture(Instant::now() + Duration::from_secs(10), false)
        .is_err());
    assert_eq!(fixture.surface.finish(), Err(super::super::unavailable(())));
    fixture.surface.report_readiness_timing();
    assert_eq!(*fixture.factory.calls.borrow(), before);
    assert!(fixture.surface.idle());
    fixture.assert_no_ceremony_data();
    Ok(())
}
