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
    fixture
        .surface
        .zero_close_buffers()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.factory.failure.set(failure);
    let deadline = Instant::now() + Duration::from_secs(10);
    fixture
        .surface
        .arm_exit_capture(selected.ceremony_id, std::rc::Rc::default(), deadline)
        .map_err(|()| "capture arm")?;
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok((fixture, deadline))
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
