#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pos_owner_bridge::fake::host::StoreOp;
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

pub(super) fn change_identity(fixture: &mut Fixture, change_after: usize) {
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
fn modeled_before_record_snapshot_requires_readable_empty_store_and_admitted_environment(
) -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    let selected = spec(40);
    fixture.factory.preload_owners.set(true);
    let browser = fixture
        .open(&selected)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(fixture.surface.before_record_fault_state(), Ok(browser));

    fixture.store.set_failing(&[StoreOp::List]);
    assert!(fixture.surface.before_record_fault_state().is_err());
    fixture.store.set_failing(&[]);
    fixture.store.preload(vec![0x80]);
    assert!(fixture.surface.before_record_fault_state().is_err());
    assert_eq!(fixture.store.records_now(), [vec![0x80]]);
    fixture
        .store
        .delete_record(&[0x80])
        .map_err(|_| "restore modeled record")?;

    fixture.factory.failure.set(Some("preload-owner"));
    assert!(fixture.surface.before_record_fault_state().is_err());
    fixture.factory.failure.set(Some("environment"));
    assert!(fixture.surface.before_record_fault_state().is_err());
    fixture.factory.failure.set(None);
    fixture
        .factory
        .environment_version
        .set("not-the-pinned-runtime");
    assert!(fixture.surface.before_record_fault_state().is_err());
    fixture.factory.environment_version.set("153.0.4234.48");

    let folder = fixture.root.join(&selected.folder_name);
    let displaced = fixture.root.join("displaced-modeled-folder");
    std::fs::rename(&folder, &displaced)?;
    assert!(fixture.surface.before_record_fault_state().is_err());
    std::fs::rename(&displaced, &folder)?;
    assert_eq!(fixture.surface.before_record_fault_state(), Ok(browser));
    assert!(fixture.surface.before_record_owners_retained());
    assert!(!fixture.surface.idle());
    fixture.assert_no_ceremony_data();
    fixture.finish()
}

#[test]
fn modeled_early_callback_invalidates_pre_record_and_renderer_observations() -> TestResult {
    for event in [NativeEvent::Frame, NativeEvent::NewWindow] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.preload_owners.set(true);
        fixture
            .factory
            .renderer_presence
            .set(Some(crate::RendererPresence::Absent));
        fixture
            .open(&spec(40))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(fixture.surface.before_record_fault_state().is_ok());
        assert_eq!(
            fixture.surface.early_renderer_presence(),
            Ok(crate::RendererPresence::Absent)
        );
        let sink = fixture
            .factory
            .sink
            .borrow()
            .clone()
            .ok_or("missing sink")?;
        let _action = sink.event(event);
        assert!(fixture.surface.before_record_fault_state().is_err());
        assert!(fixture.surface.early_renderer_presence().is_err());
        assert!(matches!(
            fixture.surface.navigate(),
            std::task::Poll::Ready(Err(_))
        ));
        assert!(!fixture.surface.idle());
        fixture.assert_no_ceremony_data();
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn modeled_pre_record_observation_refuses_activation_failure_and_later_phases() -> TestResult {
    let mut failed = Fixture::new(Creation::Ready)?;
    failed.factory.preload_owners.set(true);
    failed.factory.failure.set(Some("fit_controller"));
    let browser = failed
        .open(&spec(40))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(browser.browser_pid, 42);
    failed.factory.failure.set(None);
    assert!(failed.surface.before_record_fault_state().is_err());
    assert!(matches!(
        failed.surface.navigate(),
        std::task::Poll::Ready(Err(_))
    ));
    assert!(!failed.surface.idle());
    failed.assert_no_ceremony_data();
    failed.finish()?;

    let mut navigated = Fixture::new(Creation::Ready)?;
    navigated.factory.preload_owners.set(true);
    navigated.ready()?;
    let calls = navigated.factory.calls.borrow().clone();
    assert!(navigated.surface.before_record_fault_state().is_err());
    assert_eq!(*navigated.factory.calls.borrow(), calls);
    create_buffers(&mut navigated, 1)?;
    assert!(navigated.surface.before_record_fault_state().is_err());
    assert!(navigated.surface.early_renderer_presence().is_err());
    assert!(navigated.store.records_now().is_empty());
    assert!(!navigated.surface.idle());
    navigated.finish()
}

#[test]
fn modeled_pre_environment_retention_refuses_untrusted_observations_until_retirement() -> TestResult
{
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.environment_creation.set(Creation::Pending);
    let selected = spec(40);
    assert!(fixture.surface.open(&selected).is_pending());
    assert_eq!(fixture.surface.pre_environment_completion(), Ok(None));
    assert_eq!(
        fixture
            .surface
            .pre_environment_retention(&selected.ceremony_id),
        Some(super::super::PreEnvironmentRetention::Active)
    );

    fixture.store.set_failing(&[StoreOp::List]);
    assert!(fixture.surface.pre_environment_completion().is_err());
    assert!(fixture
        .surface
        .pre_environment_retention(&selected.ceremony_id)
        .is_none());
    fixture.store.set_failing(&[]);
    fixture.store.preload(vec![0x80]);
    assert!(fixture.surface.pre_environment_completion().is_err());
    assert!(fixture
        .surface
        .pre_environment_retention(&selected.ceremony_id)
        .is_none());
    fixture
        .store
        .delete_record(&[0x80])
        .map_err(|_| "restore modeled record")?;
    fixture.factory.window_exists.set(false);
    assert!(fixture
        .surface
        .pre_environment_retention(&selected.ceremony_id)
        .is_none());
    fixture.factory.window_exists.set(true);
    let folder = fixture.root.join(&selected.folder_name);
    let displaced = fixture.root.join("displaced-pending-folder");
    std::fs::rename(&folder, &displaced)?;
    assert!(fixture
        .surface
        .pre_environment_retention(&selected.ceremony_id)
        .is_none());
    std::fs::rename(&displaced, &folder)?;
    assert!(fixture
        .surface
        .pre_environment_retention(&spec(41).ceremony_id)
        .is_none());
    assert_eq!(fixture.surface.pre_environment_completion(), Ok(None));
    fixture.assert_no_ceremony_data();

    fixture.surface.abandon_opening();
    assert!(fixture.surface.pre_environment_completion().is_err());
    assert_eq!(
        fixture
            .surface
            .pre_environment_retention(&selected.ceremony_id),
        Some(super::super::PreEnvironmentRetention::Abandoned)
    );
    fixture
        .factory
        .environment_creation
        .set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    Ok(())
}

#[test]
fn modeled_pending_environment_event_refuses_observation_without_dropping_owners() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.environment_creation.set(Creation::Pending);
    let selected = spec(40);
    assert!(fixture.surface.open(&selected).is_pending());
    assert_eq!(fixture.surface.pre_environment_completion(), Ok(None));
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    let _action = sink.event(NativeEvent::NewWindow);
    assert!(fixture.surface.pre_environment_completion().is_err());
    assert!(!fixture.surface.idle());
    assert!(fixture.surface.native.pending());
    fixture.assert_no_ceremony_data();
    fixture.surface.abandon_opening();
    fixture
        .factory
        .environment_creation
        .set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    Ok(())
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

pub(super) fn posted_fixture(generation: u32) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    create_buffers(&mut fixture, generation)?;
    fixture
        .surface
        .post(&pos_owner_bridge::PostGuard {
            generation,
            navigation_id: pos_owner_bridge::NavigationId(7),
            served_count: 1,
        })
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.store.preload(vec![0x80]);
    fixture.factory.failure.set(Some("fault_spy"));
    Ok(fixture)
}

pub(super) fn finish_posted(mut fixture: Fixture) -> TestResult {
    fixture
        .store
        .delete_record(&[0x80])
        .map_err(|_| "restore modeled record")?;
    fixture.finish()
}

#[test]
fn modeled_posted_snapshots_require_their_distinct_reply_states() -> TestResult {
    type Snapshot = fn(&mut Surface, u8) -> Result<crate::ProcessFaultState, ()>;
    let cases: [(Snapshot, ControlState, crate::ProcessFaultPhase); 4] = [
        (
            Surface::posted_empty_fault_state,
            ControlState::Empty,
            crate::ProcessFaultPhase::PostedEmpty,
        ),
        (
            Surface::posted_writing_fault_state,
            ControlState::Writing,
            crate::ProcessFaultPhase::PostedWriting,
        ),
        (
            Surface::posted_ready_fault_state,
            ControlState::Ready,
            crate::ProcessFaultPhase::PostedReady,
        ),
        (
            Surface::releasing_fault_state,
            ControlState::ReleaseRequested,
            crate::ProcessFaultPhase::ReleasingSuccess,
        ),
    ];
    let mut fixture = posted_fixture(1)?;
    for (snapshot, expected, phase) in cases {
        for observed in [
            ControlState::Empty as u32,
            ControlState::Writing as u32,
            ControlState::Ready as u32,
            ControlState::ReleaseRequested as u32,
            u32::MAX,
        ] {
            fixture.factory.state.set(observed);
            let result = snapshot(&mut fixture.surface, 1);
            if observed == expected as u32 {
                let state = result.map_err(|()| "modeled state rejected")?;
                assert_eq!(state.phase, phase);
                assert_eq!(state.reply_state, observed);
                assert_eq!(state.generation, 1);
                assert_eq!(state.record_count, 1);
                assert_eq!(state.posts, 1);
            } else {
                assert!(result.is_err());
            }
            assert_eq!(fixture.store.records_now(), [vec![0x80]]);
            assert!(!fixture.surface.idle());
        }
        fixture.factory.state.set(expected as u32);
        fixture.store.preload(vec![0x81]);
        assert!(snapshot(&mut fixture.surface, 1).is_err());
        fixture
            .store
            .delete_record(&[0x81])
            .map_err(|_| "restore extra modeled record")?;
        fixture
            .store
            .delete_record(&[0x80])
            .map_err(|_| "remove modeled record")?;
        assert!(snapshot(&mut fixture.surface, 1).is_err());
        fixture.store.preload(vec![0x80]);
        change_identity(&mut fixture, 0);
        assert!(snapshot(&mut fixture.surface, 1).is_err());
        fixture.surface.runtime = Arc::new(Runtime(fixture.root.clone()));
        assert!(snapshot(&mut fixture.surface, 1).is_ok());
    }
    finish_posted(fixture)
}
