#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pos_owner_bridge::{BridgeError, CleanupStore, OwnerWebSurface, ProcessIdentity, RequestImage};
use pos_owner_bridge_codec::{CeremonyId, CeremonyKind, ControlState, OwnerBridgeControlV1};

use super::{spec, Creation, Fixture, Runtime, RuntimeAdmission, Surface, TestResult};
use crate::{NativeAction, NativeEvent, NativeText, ProcessFaultTarget, RetryPoint};

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

struct ChangingIdentity {
    root: PathBuf,
    change_after: usize,
    reads: AtomicUsize,
}

impl RuntimeAdmission for ChangingIdentity {
    fn root(&self) -> &Path {
        &self.root
    }

    fn identity(&self, pid: u32) -> Result<ProcessIdentity, BridgeError> {
        let changed = self.reads.fetch_add(1, Ordering::Relaxed) >= self.change_after;
        let mut identity = Runtime(self.root.clone()).identity(pid)?;
        identity.creation_filetime += u64::from(changed);
        Ok(identity)
    }
}

fn change_identity(fixture: &mut Fixture, change_after: usize) {
    let runtime = Arc::new(ChangingIdentity {
        root: fixture.root.clone(),
        change_after,
        reads: AtomicUsize::new(0),
    });
    assert_eq!(runtime.root(), fixture.root.as_path());
    fixture.surface.runtime = runtime;
}

#[test]
fn modeled_early_renderer_snapshot_rechecks_identity_and_retains_the_owner() -> TestResult {
    for change_after in [0, 1] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.preload_owners.set(true);
        fixture
            .factory
            .renderer_presence
            .set(Some(crate::RendererPresence::Absent));
        fixture
            .open(&spec(40))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert_eq!(
            fixture.surface.early_renderer_presence(),
            Ok(crate::RendererPresence::Absent)
        );
        change_identity(&mut fixture, change_after);
        assert!(fixture.surface.early_renderer_presence().is_err());
        assert!(!fixture.surface.idle());
        assert!(fixture.store.records_now().is_empty());
        fixture.surface.runtime = Arc::new(Runtime(fixture.root.clone()));
        fixture.factory.failure.set(Some("preload-owner"));
        assert!(fixture.surface.early_renderer_presence().is_err());
        fixture.factory.failure.set(Some("early_renderer_presence"));
        assert!(fixture.surface.early_renderer_presence().is_err());
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn modeled_before_record_snapshot_refuses_a_changed_browser_identity() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.preload_owners.set(true);
    let identity = fixture
        .open(&spec(40))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(fixture.surface.before_record_fault_state(), Ok(identity));
    assert!(fixture.surface.before_record_owners_retained());
    change_identity(&mut fixture, 0);
    assert!(fixture.surface.before_record_fault_state().is_err());
    assert!(fixture.store.records_now().is_empty());
    assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
    fixture.finish()
}

#[test]
fn modeled_navigation_snapshots_require_the_original_browser_and_one_record() -> TestResult {
    for awaiting_load in [false, true] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.preload_owners.set(true);
        fixture.factory.navigation_succeeds.set(true);
        fixture
            .open(&spec(40))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(fixture.surface.navigate().is_pending());
        if awaiting_load {
            let sink = fixture
                .factory
                .sink
                .borrow()
                .clone()
                .ok_or("missing sink")?;
            assert_eq!(
                sink.event(NativeEvent::Navigation {
                    uri: NativeText::fixture(crate::OWNER_URL),
                    id: 7,
                    redirected: false,
                }),
                NativeAction::Allow
            );
        }
        let snapshot: fn(&mut Surface, u32, u8) -> Result<crate::ProcessFaultMark, ()> =
            if awaiting_load {
                Surface::awaiting_load_fault_state
            } else {
                Surface::navigating_fault_state
            };
        assert!(snapshot(&mut fixture.surface, 1, 0).is_err());
        fixture.store.preload(vec![0x80]);
        assert!(snapshot(&mut fixture.surface, 1, 0).is_ok());
        assert!(snapshot(&mut fixture.surface, 2, 0).is_err());
        assert!(snapshot(&mut fixture.surface, 1, 1).is_err());
        change_identity(&mut fixture, 0);
        assert!(snapshot(&mut fixture.surface, 1, 0).is_err());
        assert_eq!(fixture.store.records_now(), [vec![0x80]]);
        fixture
            .store
            .delete_record(&[0x80])
            .map_err(|_| "restore modeled record")?;
        fixture.finish()?;
    }
    Ok(())
}

fn create_buffers(fixture: &mut Fixture, generation: u32) -> TestResult {
    let id = CeremonyId::from_bytes([40; 16]);
    let request_header = OwnerBridgeControlV1::new_request(CeremonyKind::Create, generation, id, 1)
        .map_err(|error| error.to_string())?
        .encode();
    let reply_header = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, generation, id)
        .map_err(|error| error.to_string())?
        .encode();
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes()[..64].copy_from_slice(&request_header);
    fixture
        .surface
        .create_and_write(&request, &reply_header)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(())
}

#[test]
fn modeled_posted_snapshots_require_identity_generation_record_and_post_counts() -> TestResult {
    for retry in [false, true] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.preload_owners.set(true);
        fixture.ready()?;
        let generation: u8 = if retry { 2 } else { 1 };
        create_buffers(&mut fixture, u32::from(generation))?;
        fixture.factory.state.set(ControlState::Empty as u32);
        let snapshot = |surface: &mut Surface, posts| {
            if retry {
                surface.posted_retry_fault_state(posts, RetryPoint::Second)
            } else {
                surface.posted_fault_state(posts)
            }
        };
        assert!(snapshot(&mut fixture.surface, generation).is_err());
        fixture.store.preload(vec![0x80]);
        assert!(snapshot(&mut fixture.surface, generation).is_ok());
        assert!(snapshot(&mut fixture.surface, 0).is_err());
        change_identity(&mut fixture, 0);
        assert!(snapshot(&mut fixture.surface, generation).is_err());
        assert_eq!(fixture.store.records_now(), [vec![0x80]]);
        fixture
            .store
            .delete_record(&[0x80])
            .map_err(|_| "restore modeled record")?;
        fixture.finish()?;
    }
    Ok(())
}
