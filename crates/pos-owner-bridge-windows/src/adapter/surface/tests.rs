#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::{
    BridgeError, LifecycleCode, MonotonicClock, OwnerWebSurface, ProcessIdentity, SurfaceSpec,
};
use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256};

use super::{RuntimeAdmission, Surface};
use crate::{NativeEvent, NativeFactory};
use native::{Creation, Factory};

mod exit_boundary_tests;
mod fault_admission;
mod fault_states;
pub(in crate::adapter) mod native;
mod pending_creation;
mod posting;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    factory: Rc<Factory>,
    store: FakeStore,
    loopback: FakeLoopback,
    clock: FakeClock,
    surface: Surface,
}

impl Fixture {
    fn new(creation: Creation) -> Result<Self, Box<dyn std::error::Error>> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "owner-retirement-{}-{}-{sequence}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        crate::create_private_directory(&root)?;
        let clock = FakeClock::start();
        let factory = Factory::new(creation, clock.clone());
        let native: Rc<dyn NativeFactory> = Rc::new(Rc::clone(&factory));
        let store = FakeStore::default();
        let loopback = FakeLoopback::default();
        let deadline = clock.now() + Duration::from_secs(30);
        let mut surface = Surface::new(
            native,
            Arc::new(Runtime(root.clone())),
            root.clone(),
            Box::new(loopback.clone()),
            Box::new(store.clone()),
            Box::new(clock.clone()),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        surface.set_deadline(deadline);
        Ok(Self {
            root,
            factory,
            store,
            loopback,
            clock,
            surface,
        })
    }

    fn exit(&self) {
        if let Some(sink) = self.factory.sink.borrow().as_ref() {
            sink.event(NativeEvent::BrowserExited { pid: 42 });
        }
    }

    fn open(
        &mut self,
        spec: &SurfaceSpec,
    ) -> Result<ProcessIdentity, pos_owner_bridge::SurfaceError> {
        loop {
            if let Poll::Ready(result) = self.surface.open(spec) {
                return result;
            }
            // Only the host/test harness pumps; a surface poll must return first.
            self.surface.pump().map_err(super::unavailable)?;
        }
    }

    fn assert_no_ceremony_data(&self) {
        assert!(self.store.records_now().is_empty());
        for forbidden in ["navigate", "create_buffers", "post"] {
            assert!(!self.factory.calls.borrow().contains(&forbidden));
        }
    }

    fn ready(&mut self) -> TestResult {
        self.factory.navigation_succeeds.set(true);
        self.open(&spec(40))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(self.surface.navigate().is_pending());
        let sink = self.factory.sink.borrow().clone().ok_or("missing sink")?;
        assert_eq!(
            sink.event(NativeEvent::Navigation {
                uri: crate::NativeText::fixture(crate::OWNER_URL),
                id: 7,
                redirected: false,
            }),
            crate::NativeAction::Allow
        );
        sink.event(NativeEvent::DomLoaded {
            id: 7,
            uri: crate::NativeText::fixture(crate::OWNER_URL),
        });
        assert!(matches!(
            self.surface.navigate(),
            Poll::Ready(Ok(pos_owner_bridge::NavigationId(7)))
        ));
        self.loopback.set_served(1, true);
        Ok(())
    }

    fn finish(&mut self) -> TestResult {
        self.factory.failure.set(None);
        self.factory.close_uncertain.set(false);
        self.surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        self.exit();
        self.surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(self.surface.idle());
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.root);
    }
}

pub(in crate::adapter) struct Runtime(pub(in crate::adapter) PathBuf);

impl RuntimeAdmission for Runtime {
    fn root(&self) -> &Path {
        &self.0
    }
    fn identity(&self, pid: u32) -> Result<ProcessIdentity, BridgeError> {
        Ok(ProcessIdentity {
            browser_pid: pid,
            creation_filetime: 1,
            image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
        })
    }
}

fn spec(value: u8) -> SurfaceSpec {
    let ceremony_id = CeremonyId::from_bytes([value; 16]);
    SurfaceSpec {
        ceremony_id,
        folder_name: pos_owner_bridge::folder_name(&ceremony_id),
        owner_window: None,
    }
}

#[test]
fn outer_event_ticks_retry_failed_close_until_own_exit_without_reopening() -> TestResult {
    for failure in ["unsubscribe_view", "close_controller"] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        fixture.factory.failure.set(Some(failure));
        assert!(fixture.surface.close_controller().is_err());
        let attempts = fixture
            .factory
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == failure)
            .count();
        fixture.clock.advance(Duration::from_secs(8));
        let now = fixture.clock.now();
        let _event = fixture.surface.take_event();
        assert!(
            fixture
                .factory
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == failure)
                .count()
                > attempts
        );
        assert!(fixture.surface.finish().is_err());
        fixture.factory.failure.set(None);
        let _event = fixture.surface.take_event();
        assert!(fixture.surface.finish().is_err());
        assert_eq!(fixture.clock.now(), now);
        assert!(matches!(
            fixture.surface.open(&spec(99)),
            Poll::Ready(Err(_))
        ));
        if let Some(sink) = fixture.factory.sink.borrow().as_ref() {
            sink.event(NativeEvent::BrowserExited { pid: 43 });
        }
        assert!(fixture.surface.finish().is_err());
        assert!(!fixture.surface.idle());
        fixture.exit();
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(fixture.surface.idle());
    }
    Ok(())
}

#[test]
fn reused_surface_observes_only_the_admitted_opening() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    fixture.factory.failure.set(Some("close_buffers"));
    assert!(fixture.surface.close_controller().is_err());
    let first = fixture
        .surface
        .initial_close_observation()
        .ok_or("missing close observation")?;
    assert!(!first.buffers_closed);
    assert!(matches!(
        fixture.surface.open(&spec(41)),
        Poll::Ready(Err(_))
    ));
    assert_eq!(fixture.surface.initial_close_observation(), Some(first));
    fixture.finish()?;
    fixture
        .open(&spec(41))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(fixture.surface.initial_close_observation(), None);
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    let second = fixture
        .surface
        .initial_close_observation()
        .ok_or("missing new close observation")?;
    assert!(second.removed.is_ok());
    assert!(second.buffers_closed);
    fixture.exit();
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(())
}

#[test]
#[cfg(test)]
fn quarantined_fault_refuses_missing_state_and_unheld_keeper() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    assert!(!fixture.surface.native.preload_fault_owners_retained());
    assert!(fixture.surface.generation.is_none());
    assert!(fixture.store.records_now().is_empty());
    assert!(fixture.surface.native.early_renderer_presence().is_err());
    assert!(fixture.surface.quarantined_fault_state().is_err());
    let before = fixture.factory.calls.borrow().clone();
    let seal = crate::FaultSeal {
        trace: Rc::new(std::cell::RefCell::new(Vec::new())),
        deadline: std::time::Instant::now() + Duration::from_secs(1),
    };
    assert!(fixture
        .surface
        .inject_quarantined_fault(
            crate::ProcessFaultTarget::Renderer,
            seal,
            Rc::new(std::cell::Cell::new(false)),
        )
        .is_err());
    assert_eq!(*fixture.factory.calls.borrow(), before);
    fixture.finish()
}

#[test]
fn synchronous_navigation_failure_refuses_readiness_until_owned_exit() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.navigation_succeeds.set(true);
    fixture.factory.fail_during_navigation.set(true);
    fixture
        .open(&spec(42))
        .map_err(pos_owner_bridge::SurfaceError::error)?;

    assert!(matches!(fixture.surface.navigate(), Poll::Ready(Err(error))
        if error.error() == BridgeError::Lifecycle(LifecycleCode::NavigationViolation)));
    assert!(matches!(fixture.surface.navigate(), Poll::Ready(Err(error))
        if error.error() == BridgeError::Lifecycle(LifecycleCode::NavigationViolation)));
    assert_eq!(
        fixture
            .factory
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "navigate")
            .count(),
        1
    );
    assert!(!fixture.surface.buffers);
    assert!(!fixture.factory.calls.borrow().contains(&"create_buffers"));
    assert!(!fixture.factory.calls.borrow().contains(&"post"));
    assert!(fixture.store.records_now().is_empty());
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.finish().is_err());
    assert!(!fixture.surface.idle());
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(NativeEvent::BrowserExited { pid: 43 });
    assert!(fixture.surface.finish().is_err());
    assert!(!fixture.surface.idle());
    fixture.exit();
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.idle());
    Ok(())
}

#[test]
fn native_creation_and_navigation_polls_return_before_host_dispatch() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.foreground.set(false);
    fixture.factory.navigation_succeeds.set(true);
    let selected = spec(6);
    let started = fixture.clock.now();
    for _ in 0..2 {
        assert!(fixture.surface.open(&selected).is_pending());
        assert_eq!(fixture.clock.now(), started);
    }
    assert!(
        matches!(fixture.surface.open(&selected), Poll::Ready(Ok(identity)) if identity.browser_pid == 42)
    );
    assert!(fixture.surface.navigate().is_pending());
    assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
    fixture.factory.foreground.set(true);
    for _ in 0..3 {
        assert!(fixture.surface.navigate().is_pending());
    }
    assert_eq!(
        fixture
            .factory
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "navigate")
            .count(),
        1
    );
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing event sink")?;
    assert_eq!(
        sink.event(NativeEvent::Navigation {
            uri: crate::NativeText::fixture(crate::OWNER_URL),
            id: 7,
            redirected: false,
        }),
        crate::NativeAction::Allow
    );
    assert!(matches!(
        fixture.surface.navigate(),
        Poll::Ready(Ok(pos_owner_bridge::NavigationId(7)))
    ));
    assert_eq!(fixture.clock.now(), started);
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.exit();
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.idle());
    Ok(())
}

#[test]
fn pending_browser_observation_rechecks_controller_ownership_and_completion() -> TestResult {
    for failure in [
        None,
        Some("pending-owner-after"),
        Some("pending-callback-after"),
    ] {
        let mut fixture = Fixture::new(Creation::Pending)?;
        let selected = spec(6);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        fixture.factory.failure.set(failure);
        let observation = fixture.surface.prepare_pending_opening_browser();
        if failure.is_none() {
            assert!(matches!(observation, Ok(None)));
        } else {
            assert!(observation.is_err());
        }
        assert_eq!(
            fixture
                .factory
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == "create_controller")
                .count(),
            1
        );
        assert_eq!(
            fixture
                .factory
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == "pending_candidate")
                .count(),
            1
        );
        fixture.assert_no_ceremony_data();
        fixture.factory.failure.set(None);
        fixture.surface.abandon_opening();
        assert!(!fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(!fixture.surface.idle());
        fixture.factory.creation.set(Creation::CallbackFailure);
        assert!(fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(fixture.surface.idle());
        fixture.assert_no_ceremony_data();
    }
    Ok(())
}

#[test]
fn abandoned_pending_open_keeps_the_original_completion_owned() -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let selected = spec(7);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(matches!(
        fixture.surface.open(&spec(8)),
        Poll::Ready(Err(_))
    ));
    assert!(fixture.surface.open(&selected).is_pending());
    fixture.surface.abandon_opening();
    assert!(!fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(!fixture.surface.idle());
    fixture.factory.creation.set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    fixture.assert_no_ceremony_data();
    Ok(())
}

#[test]
fn failed_controller_without_exit_preserves_orphan_and_allows_fresh_ceremony() -> TestResult {
    for creation in [Creation::SynchronousFailure, Creation::CallbackFailure] {
        let mut fixture = Fixture::new(creation)?;
        let failed = spec(1);
        assert!(fixture.open(&failed).is_err());
        assert!(fixture
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(fixture.surface.idle());
        assert!(fixture.root.join(&failed.folder_name).is_dir());
        assert!(fixture.store.removed_folders().is_empty());
        assert_eq!(
            &fixture.factory.calls.borrow()[3..],
            &[
                "unsubscribe_view",
                "unsubscribe_exit",
                "drop_environment",
                "destroy_window"
            ]
        );
        fixture.assert_no_ceremony_data();

        fixture.factory.creation.set(Creation::Ready);
        let fresh = spec(2);
        assert_eq!(
            fixture
                .open(&fresh)
                .map_err(pos_owner_bridge::SurfaceError::error)?
                .browser_pid,
            42
        );
        assert_ne!(failed.folder_name, fresh.folder_name);
        assert!(fixture.root.join(&fresh.folder_name).is_dir());
        fixture.assert_no_ceremony_data();
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        fixture.exit();
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(fixture.surface.idle());
        assert_eq!(fixture.store.removed_folders(), vec![fresh.folder_name]);
        assert!(fixture.root.join(failed.folder_name).is_dir());
    }
    Ok(())
}

#[test]
fn controller_without_view_waits_for_its_environment_exit() -> TestResult {
    let mut fixture = Fixture::new(Creation::MissingView)?;
    let failed = spec(3);
    assert!(fixture.open(&failed).is_err());
    assert!(!fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(!fixture.surface.idle());
    assert!(fixture.store.removed_folders().is_empty());
    assert!(!fixture.factory.calls.borrow().contains(&"drop_environment"));
    assert!(fixture.factory.calls.borrow().contains(&"close_controller"));
    fixture.assert_no_ceremony_data();
    fixture.exit();
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    assert_eq!(fixture.store.removed_folders(), vec![failed.folder_name]);
    Ok(())
}

#[test]
fn timed_out_controller_keeps_native_owners_until_the_late_callback() -> TestResult {
    let mut fixture = Fixture::new(Creation::Pending)?;
    let failed = spec(4);
    assert!(fixture.open(&failed).is_err());
    assert!(!fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(!fixture.surface.idle());
    assert!(!fixture.factory.calls.borrow().contains(&"drop_environment"));
    assert!(!fixture.factory.calls.borrow().contains(&"destroy_window"));
    assert!(fixture.store.removed_folders().is_empty());
    fixture.assert_no_ceremony_data();

    fixture.factory.creation.set(Creation::CallbackFailure);
    assert!(fixture
        .surface
        .poll_failed_open()
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(fixture.surface.idle());
    assert!(fixture.root.join(&failed.folder_name).is_dir());
    assert!(fixture.store.removed_folders().is_empty());
    fixture.factory.creation.set(Creation::Ready);
    fixture
        .surface
        .set_deadline(fixture.clock.now() + Duration::from_secs(30));
    assert!(fixture.open(&spec(5)).is_ok());
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.exit();
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.idle());
    fixture.assert_no_ceremony_data();
    Ok(())
}
