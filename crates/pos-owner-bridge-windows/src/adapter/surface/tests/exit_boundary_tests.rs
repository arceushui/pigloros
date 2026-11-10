#![cfg(windows)]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use pos_owner_bridge::{CleanupStore, OwnerWebSurface, RequestImage};
use pos_owner_bridge_codec::{CeremonyId, CeremonyKind, CleanupRecordV1, OwnerBridgeControlV1};

use super::{spec, Creation, Fixture, TestResult};
use crate::adapter::surface::ExitBoundary;

fn closed_fixture() -> Result<(Fixture, Instant), Box<dyn std::error::Error>> {
    closed_fixture_with_failure(None)
}

fn closed_fixture_with_failure(
    failure: Option<&'static str>,
) -> Result<(Fixture, Instant), Box<dyn std::error::Error>> {
    let (mut fixture, deadline) = prepared_fixture(failure, Duration::from_secs(10))?;
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok((fixture, deadline))
}

fn prepared_fixture(
    failure: Option<&'static str>,
    window: Duration,
) -> Result<(Fixture, Instant), Box<dyn std::error::Error>> {
    let mut fixture = buffered_fixture()?;
    fixture
        .surface
        .zero_close_buffers()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.factory.failure.set(failure);
    let deadline = Instant::now() + window;
    fixture
        .surface
        .arm_exit_capture(spec(40).ceremony_id, std::rc::Rc::default(), deadline)
        .map_err(|()| "capture arm")?;
    Ok((fixture, deadline))
}

fn buffered_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    let selected = spec(40);
    let identity = fixture.surface.identity.ok_or("missing browser identity")?;
    let record = CleanupRecordV1::new(
        selected.ceremony_id,
        &selected.folder_name,
        identity.browser_pid,
        identity.creation_filetime,
        identity.image_path_sha256,
    )
    .map_err(|error| error.to_string())?;
    let mut encoded = [0; 4096];
    let size = pos_owner_bridge_codec::encode_cleanup_record(&record, &mut encoded)
        .map_err(|error| error.to_string())?;
    fixture
        .store
        .write_record(&encoded[..size])
        .map_err(|_| "record")?;
    let id = CeremonyId::from_bytes([1; 16]);
    let request_header = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, id, 1)
        .map_err(|error| error.to_string())?
        .encode();
    let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, id)
        .map_err(|error| error.to_string())?
        .encode();
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes()[..64].copy_from_slice(&request_header);
    fixture
        .surface
        .create_and_write(&request, &reply)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(fixture)
}

#[test]
fn fresh_success_provenance_binds_record_and_matching_exit_to_owner() -> TestResult {
    let mut fixture = buffered_fixture()?;
    let ceremony = spec(40).ceremony_id;
    let browser = fixture
        .surface
        .fresh_success_provenance(ceremony)
        .map_err(|()| "fresh provenance")?;
    assert!(fixture
        .surface
        .fresh_success_provenance(spec(41).ceremony_id)
        .is_err());
    fixture.surface.generation = Some(2);
    assert!(fixture.surface.fresh_success_provenance(ceremony).is_err());
    fixture.surface.generation = Some(1);
    let records = fixture.store.records().map_err(|_| "records")?;
    let [original] = records.as_slice() else {
        return Err("missing original record".into());
    };
    fixture
        .store
        .delete_record(original)
        .map_err(|_| "delete record")?;
    let selected = spec(40);
    let wrong = CleanupRecordV1::new(
        ceremony,
        &selected.folder_name,
        browser.browser_pid + 1,
        browser.creation_filetime,
        browser.image_path_sha256,
    )
    .map_err(|error| error.to_string())?;
    let mut encoded = [0; 4096];
    let size = pos_owner_bridge_codec::encode_cleanup_record(&wrong, &mut encoded)
        .map_err(|error| error.to_string())?;
    fixture
        .store
        .write_record(&encoded[..size])
        .map_err(|_| "wrong record")?;
    assert!(fixture.surface.fresh_success_provenance(ceremony).is_err());
    fixture
        .store
        .delete_record(&encoded[..size])
        .map_err(|_| "delete wrong record")?;
    fixture
        .store
        .write_record(original)
        .map_err(|_| "restore record")?;
    assert!(matches!(
        fixture.surface.open(&spec(41)),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(!fixture.surface.fresh_success_own_exit(browser));
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(crate::NativeEvent::BrowserExited {
        pid: browser.browser_pid,
    });
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.fresh_success_own_exit(browser));
    Ok(())
}

#[test]
fn exit_capture_refuses_unavailable_or_mismatched_handle_without_releasing_owner() -> TestResult {
    for failure in ["retain_exit", "mismatched_exit_handle"] {
        let (mut fixture, deadline) = closed_fixture_with_failure(Some(failure))?;
        fixture.factory.failure.set(None);
        assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
        assert!(fixture
            .surface
            .consume_exit_capture(deadline, true)
            .is_err());
        assert!(matches!(
            fixture.surface.open(&spec(41)),
            std::task::Poll::Ready(Err(_))
        ));
        assert!(!fixture.store.records_now().is_empty());
        assert!(fixture.surface.finish().is_err());
    }
    Ok(())
}

#[test]
fn exit_boundary_requires_existing_matching_exit_and_keeps_it_for_retirement() -> TestResult {
    let (mut fixture, deadline) = closed_fixture()?;
    assert!(matches!(
        fixture.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::ObjectExitedAwaitingSdk(_))
    ));
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(crate::NativeEvent::BrowserExited { pid: 42 });
    assert!(matches!(
        fixture.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::AlreadyExited(_))
    ));
    assert!(fixture
        .surface
        .classify_exit_boundary(Instant::now())
        .is_err());
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(())
}

#[test]
fn exit_boundary_refuses_foreign_or_independently_invalid_events() -> TestResult {
    for foreign in [true, false] {
        let (mut fixture, deadline) = closed_fixture()?;
        let sink = fixture
            .factory
            .sink
            .borrow()
            .clone()
            .ok_or("missing sink")?;
        if foreign {
            sink.event(crate::NativeEvent::BrowserExited { pid: 43 });
        } else {
            fixture.surface.events.controller_lost();
        }
        sink.event(crate::NativeEvent::BrowserExited { pid: 42 });
        assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
    }
    Ok(())
}

#[test]
fn exit_capture_distinguishes_active_and_exited_and_refuses_uncertainty() -> TestResult {
    let (mut fixture, deadline) = closed_fixture()?;
    fixture.factory.exit_code.set(None);
    assert!(matches!(
        fixture.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::ActiveStatus(_))
    ));
    fixture.factory.failure.set(Some("exit_membership_empty"));
    assert!(matches!(
        fixture.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::ActiveStatus(_))
    ));
    fixture.factory.failure.set(None);
    assert!(matches!(
        fixture.surface.open(&spec(41)),
        std::task::Poll::Ready(Err(_))
    ));
    fixture.factory.failure.set(Some("exit_observation"));
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    fixture.factory.failure.set(None);
    fixture.factory.failure.set(Some("exit_membership"));
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    fixture.factory.failure.set(None);
    fixture.factory.exit_code.set(Some(17));
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    fixture.factory.exit_code.set(Some(0));
    assert!(matches!(
        fixture.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::ObjectExitedAwaitingSdk(_))
    ));
    fixture.surface.generation = Some(2);
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    fixture.surface.generation = Some(1);
    let identity = fixture
        .surface
        .identity
        .as_mut()
        .ok_or("missing identity")?;
    identity.creation_filetime += 1;
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    fixture
        .surface
        .identity
        .as_mut()
        .ok_or("missing identity")?
        .creation_filetime -= 1;
    assert!(fixture
        .surface
        .consume_exit_capture(deadline, true)
        .is_err());
    assert!(fixture
        .surface
        .consume_exit_capture(deadline, false)
        .is_err());
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
    Ok(())
}

#[test]
fn active_exit_capture_is_one_use_and_retains_ordinary_ownership() -> TestResult {
    let (mut fixture, deadline) = closed_fixture()?;
    fixture.factory.exit_code.set(None);
    let handle = fixture
        .surface
        .consume_exit_capture(deadline, true)
        .map_err(|()| "active capture")?;
    assert_eq!(handle.exit_code(), Ok(Some(0x535)));
    assert!(fixture
        .surface
        .consume_exit_capture(deadline, true)
        .is_err());
    assert!(matches!(
        fixture.surface.open(&spec(41)),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(!fixture.store.records_now().is_empty());
    assert!(fixture.surface.finish().is_err());
    Ok(())
}

#[test]
fn final_exit_status_is_distinct_from_earlier_required_identity_observation() -> TestResult {
    let (mut fixture, deadline) = closed_fixture()?;
    let handle = fixture
        .surface
        .consume_exit_capture(deadline, false)
        .map_err(|()| "required pre-exit observation")?;
    fixture.factory.failure.set(Some("exit_observation"));
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(crate::NativeEvent::BrowserExited { pid: 42 });
    assert!(fixture.surface.matching_exit_event());
    assert_eq!(handle.exit_code(), Ok(Some(0)));
    fixture.factory.failure.set(Some("exit_final_query"));
    assert_eq!(handle.exit_code(), Err(()));
    assert!(!fixture.store.records_now().is_empty());
    fixture.factory.failure.set(None);
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(())
}

fn assert_retained_without_fault(fixture: &mut Fixture) {
    assert!(!fixture.factory.calls.borrow().contains(&"terminate_exit"));
    assert!(matches!(
        fixture.surface.open(&spec(41)),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(!fixture.store.records_now().is_empty());
    assert!(fixture.surface.finish().is_err());
}

#[test]
fn exit_fault_refuses_wrong_phase_and_expired_original_deadline() -> TestResult {
    let (mut wrong_phase, deadline) = prepared_fixture(None, Duration::from_secs(10))?;
    assert!(wrong_phase
        .surface
        .consume_exit_capture(deadline, true)
        .is_err());
    wrong_phase
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(wrong_phase
        .surface
        .consume_exit_capture(deadline, false)
        .is_err());
    assert_retained_without_fault(&mut wrong_phase);

    let (mut expired, deadline) = prepared_fixture(None, Duration::from_secs(1))?;
    expired
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    expired.factory.exit_code.set(None);
    assert!(matches!(
        expired.surface.classify_exit_boundary(deadline),
        Ok(ExitBoundary::ActiveStatus(_))
    ));
    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    assert!(expired
        .surface
        .consume_exit_capture(deadline, true)
        .is_err());
    assert!(expired
        .surface
        .consume_exit_capture(deadline, false)
        .is_err());
    assert_retained_without_fault(&mut expired);
    Ok(())
}

#[test]
fn exit_fault_refuses_malformed_or_nonempty_missing_membership() -> TestResult {
    for failure in ["exit_membership_missing", "exit_membership_malformed"] {
        let (mut fixture, deadline) = closed_fixture()?;
        fixture.factory.exit_code.set(None);
        fixture.factory.failure.set(Some(failure));
        assert!(fixture
            .surface
            .consume_exit_capture(deadline, true)
            .is_err());
        assert!(fixture
            .surface
            .consume_exit_capture(deadline, false)
            .is_err());
        assert_retained_without_fault(&mut fixture);
    }
    Ok(())
}
