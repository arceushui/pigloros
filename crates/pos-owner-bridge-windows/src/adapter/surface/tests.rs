#![cfg(windows)]
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
use pos_owner_bridge::{
    BridgeError, MonotonicClock, OwnerWebSurface, ProcessIdentity, SurfaceSpec,
};
use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256};

use super::{RuntimeAdmission, Surface};
use crate::{NativeEvent, NativeFactory};
use native::{Creation, Factory};

mod native;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    factory: Rc<Factory>,
    store: FakeStore,
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
        let deadline = clock.now() + Duration::from_secs(30);
        let mut surface = Surface::new(
            native,
            Arc::new(Runtime(root.clone())),
            root.clone(),
            Box::<FakeLoopback>::default(),
            Box::new(store.clone()),
            Box::new(clock.clone()),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        surface.set_deadline(deadline);
        Ok(Self {
            root,
            factory,
            store,
            clock,
            surface,
        })
    }

    fn exit(&self) {
        if let Some(sink) = self.factory.sink.borrow().as_ref() {
            sink.event(NativeEvent::BrowserExited { pid: 42 });
        }
    }

    fn assert_no_ceremony_data(&self) {
        assert!(self.store.records_now().is_empty());
        for forbidden in ["navigate", "create_buffers", "post"] {
            assert!(!self.factory.calls.borrow().contains(&forbidden));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.root);
    }
}

struct Runtime(PathBuf);

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
fn failed_controller_without_exit_preserves_orphan_and_allows_fresh_ceremony() -> TestResult {
    for creation in [Creation::SynchronousFailure, Creation::CallbackFailure] {
        let mut fixture = Fixture::new(creation)?;
        let failed = spec(1);
        assert!(fixture.surface.open(&failed).is_err());
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
                .surface
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
    assert!(fixture.surface.open(&failed).is_err());
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
    assert!(fixture.surface.open(&failed).is_err());
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
    assert!(fixture.surface.open(&spec(5)).is_ok());
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
