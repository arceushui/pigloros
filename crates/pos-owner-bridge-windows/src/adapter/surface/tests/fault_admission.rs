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

use super::{spec, Creation, Fixture, RuntimeAdmission, TestResult};
use crate::{EventSink, FaultSeal, NativeEvent, ProcessFaultMark};

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
