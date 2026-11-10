#![cfg(windows)]
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use pos_owner_bridge::{CleanupStore, OwnerWebSurface, RequestImage};
use pos_owner_bridge_codec::{CeremonyId, CeremonyKind, CleanupRecordV1, OwnerBridgeControlV1};

use super::{spec, Creation, Fixture, TestResult};
use crate::adapter::surface::ExitBoundary;

fn closed_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
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
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(fixture)
}

#[test]
fn exit_boundary_requires_existing_matching_exit_and_keeps_it_for_retirement() -> TestResult {
    let mut fixture = closed_fixture()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    assert!(fixture.surface.classify_exit_boundary(deadline).is_err());
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
        let mut fixture = closed_fixture()?;
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
        assert!(fixture
            .surface
            .classify_exit_boundary(Instant::now() + Duration::from_secs(10))
            .is_err());
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
    }
    Ok(())
}
