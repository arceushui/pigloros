#![cfg(windows)]
#![forbid(unsafe_code)]

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::ceremony::plan::CeremonyPlan;
use pos_owner_bridge::channel::ChannelHost;
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{
    CeremonyHost, CleanupStore, OwnerWebSurface, SurfaceEvent, SurfaceSpec, SystemClock,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, OwnerUserHandle, PrfInput, WebAuthnChallenge,
};

use super::{
    channel, SharedLoopback, Surface, WindowsCleanupStore, WindowsOwnerHost, Worker, UNAVAILABLE,
};
use crate::adapter::native_tests::{FixtureRoot, TestResult};
use crate::adapter::surface::tests::native::{Creation, Factory};
use crate::adapter::surface::tests::Runtime;
use crate::{
    Failure, NativeError, NativeEvent, NativeFactory, NativeOperations, NativePulse, Operation,
    StaPump,
};

struct FailingFactory(Arc<AtomicBool>);

impl NativeFactory for FailingFactory {
    fn session(&self) -> crate::NativeResult<Box<dyn NativeOperations>> {
        Err(failed())
    }
}

impl StaPump for FailingFactory {
    fn next(&self) -> crate::NativeResult<NativePulse> {
        Err(failed())
    }

    fn stop(&mut self) -> crate::NativeResult<()> {
        Ok(())
    }
}

impl Drop for FailingFactory {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct PumpFactory {
    inner: Rc<Factory>,
    pulse: crate::NativeResult<NativePulse>,
}

impl NativeFactory for PumpFactory {
    fn session(&self) -> crate::NativeResult<Box<dyn NativeOperations>> {
        self.inner.session()
    }
}

impl StaPump for PumpFactory {
    fn next(&self) -> crate::NativeResult<NativePulse> {
        self.pulse
    }

    fn stop(&mut self) -> crate::NativeResult<()> {
        Ok(())
    }
}

const fn failed() -> NativeError {
    NativeError {
        operation: Operation::Sta,
        failure: Failure::CallFailed,
    }
}

struct Fixture {
    root: FixtureRoot,
    worker: Worker,
    owner: Option<ChannelHost>,
    model: Rc<Factory>,
}

impl Fixture {
    fn new(pulse: crate::NativeResult<NativePulse>) -> Result<Self, Box<dyn std::error::Error>> {
        let root = FixtureRoot::new()?;
        let model = Factory::new(Creation::Ready, FakeClock::start());
        let factory: Rc<dyn NativeFactory> = Rc::new(PumpFactory {
            inner: Rc::clone(&model),
            pulse,
        });
        let loopback = SharedLoopback::start()?;
        let store = WindowsCleanupStore::open(root.0.clone())?;
        let mut surface = Surface::new(
            factory,
            Arc::new(Runtime(root.0.clone())),
            root.0.clone(),
            Box::new(loopback.clone()),
            Box::new(store.clone()),
            Box::new(SystemClock),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        surface.set_deadline(Instant::now() + Duration::from_secs(30));
        let (owner, endpoint) = channel();
        Ok(Self {
            root,
            worker: Worker::new(endpoint, surface, loopback, store),
            owner: Some(owner),
            model,
        })
    }

    fn exchange<T: Send + 'static>(
        &mut self,
        request: impl FnOnce(&mut ChannelHost) -> T + Send + 'static,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let mut owner = self.owner.take().ok_or("missing owner channel")?;
        let caller = std::thread::spawn(move || {
            let reply = request(&mut owner);
            (owner, reply)
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !caller.is_finished() {
            self.worker.receive();
            self.worker.step();
            self.worker.cleanup();
            self.worker.pump();
            assert!(
                Instant::now() < deadline,
                "modeled owner request did not return"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let (owner, reply) = caller.join().map_err(|_| "owner caller panicked")?;
        self.owner = Some(owner);
        Ok(reply)
    }

    fn finish(self) -> TestResult {
        assert!(self.worker.surface.idle());
        drop(self.owner);
        drop(self.worker);
        drop(self.model);
        self.root.remove()
    }
}

#[derive(Clone, Copy)]
enum FailurePoint {
    Factory,
    Panic,
    Session,
}

#[test]
fn failed_startup_constructs_on_the_worker_and_releases_owners_before_return() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime_path = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by the host fixture")?;
    for point in [
        FailurePoint::Factory,
        FailurePoint::Panic,
        FailurePoint::Session,
    ] {
        let root = FixtureRoot::new()?;
        let runtime = crate::verify_fixed_runtime(std::path::Path::new(&runtime_path), &root.0)?;
        let loopback = SharedLoopback::start()?;
        let store = WindowsCleanupStore::open(root.0.clone())?;
        let dropped = Arc::new(AtomicBool::new(false));
        let on_worker = Arc::new(AtomicBool::new(false));
        let captured_drop = Arc::clone(&dropped);
        let captured_worker = Arc::clone(&on_worker);
        let caller = std::thread::current().id();
        let outcome = WindowsOwnerHost::spawn_with_factory(
            runtime,
            root.0.clone(),
            loopback,
            store,
            move || {
                captured_worker.store(std::thread::current().id() != caller, Ordering::Release);
                let factory = FailingFactory(captured_drop);
                match point {
                    FailurePoint::Factory => Err(failed()),
                    FailurePoint::Panic => panic!("modeled native factory panic"),
                    FailurePoint::Session => Ok(factory),
                }
            },
        );
        assert_eq!(outcome.err(), Some(UNAVAILABLE));
        assert!(on_worker.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
        root.remove()?;
    }
    Ok(())
}

#[test]
fn worker_pump_failure_reports_loss_and_retains_pending_native_owners() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (pulse, lost) in [
        (Ok(NativePulse::Timer), false),
        (Ok(NativePulse::Dispatched), false),
        (Ok(NativePulse::Quit), true),
        (Err(failed()), true),
    ] {
        let mut fixture = Fixture::new(pulse)?;
        let ceremony_id = CeremonyId::from_bytes([141; 16]);
        let spec = SurfaceSpec {
            ceremony_id,
            folder_name: pos_owner_bridge::folder_name(&ceremony_id),
            owner_window: None,
        };
        assert!(fixture.worker.surface.open(&spec).is_pending());
        let calls = fixture.model.calls.borrow().clone();
        fixture.worker.pump();
        assert_eq!(
            matches!(
                fixture.worker.surface.take_event(),
                Some(SurfaceEvent::ControllerLost)
            ),
            lost
        );
        assert_eq!(*fixture.model.calls.borrow(), calls);
        assert!(!fixture.worker.surface.idle());
        assert!(Rc::strong_count(&fixture.model) > 1);
        assert!(fixture.root.0.join(&spec.folder_name).is_dir());
        fixture.worker.surface.abandon_opening();
        assert!(fixture
            .worker
            .surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        fixture.finish()?;
    }
    Ok(())
}

fn driver(value: u8) -> CeremonyDriver {
    CeremonyDriver::for_test(CeremonyPlan::for_test(
        CeremonyKind::Create,
        CeremonyId::from_bytes([value; 16]),
        WebAuthnChallenge::from_bytes([1; 32]),
        OwnerUserHandle::from_bytes([2; 32]),
        PrfInput::from_bytes([3; 32]),
        Instant::now(),
    ))
}

#[test]
fn host_facade_preserves_the_driver_when_its_channel_is_absent() -> TestResult {
    // Exercise the private absent-channel guard through the CeremonyHost seam.
    let mut host = WindowsOwnerHost {
        channel: None,
        worker: None,
    };
    let reply = host.run(driver(142));
    assert_eq!(reply.result.err(), Some(UNAVAILABLE));
    let driver = reply.driver.ok_or("caller driver was lost")?;
    assert!(driver.request_clear());
    assert_eq!(driver.posts(), 0);
    assert!(driver.first_receipt_at().is_none());
    let poll = host.poll_quarantine();
    assert!(!poll.remaining && poll.driver.is_none());
    Ok(())
}

#[test]
fn host_channel_retains_quarantine_and_returns_its_recovered_driver_once() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let mut fixture = Fixture::new(Ok(NativePulse::Timer))?;
    fixture.model.failure.set(Some("close_controller"));
    let reply = fixture.exchange(|owner| owner.run(driver(143)))?;
    assert!(reply.driver.is_none());
    assert!(matches!(
        reply.result.err(),
        Some(pos_owner_bridge::BridgeError::Quarantine(_))
    ));
    assert!(fixture.worker.quarantined);
    assert!(!fixture.worker.surface.idle());
    assert_eq!(fixture.worker.store.records()?.len(), 1);
    let busy = fixture.exchange(|owner| owner.run(driver(144)))?;
    assert_eq!(busy.result.err(), Some(UNAVAILABLE));
    assert!(busy
        .driver
        .is_some_and(|driver| driver.request_clear() && driver.posts() == 0));

    fixture.model.failure.set(None);
    fixture.worker.cleanup();
    assert!(fixture.worker.surface.exit_fault_phase_reached());
    assert!(fixture.worker.quarantined);
    assert_eq!(fixture.worker.store.records()?.len(), 1);
    let sink = fixture
        .model
        .sink
        .borrow()
        .clone()
        .ok_or("missing modeled exit sink")?;
    let _action = sink.event(NativeEvent::BrowserExited { pid: 43 });
    fixture.worker.cleanup();
    assert!(fixture.worker.quarantined);
    assert!(fixture.worker.recovered.is_empty());
    let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
    fixture.worker.cleanup();
    assert!(!fixture.worker.quarantined);
    assert!(fixture.worker.surface.idle());
    assert!(fixture.worker.store.records()?.is_empty());
    assert!(fixture.worker.store.folders()?.is_empty());
    assert_eq!(fixture.worker.recovered.len(), 1);
    let recovered = fixture.exchange(CeremonyHost::poll_quarantine)?;
    assert!(!recovered.remaining);
    let completed = recovered.driver.ok_or("recovered driver was lost")?;
    assert!(completed.request_clear());
    let calls = fixture.model.calls.borrow().clone();
    let repeated = fixture.exchange(move |owner| owner.run(completed))?;
    assert_eq!(repeated.result.err(), Some(UNAVAILABLE));
    assert!(repeated.driver.is_some());
    assert!(!fixture.worker.quarantined);
    assert_eq!(*fixture.model.calls.borrow(), calls);
    let again = fixture.exchange(CeremonyHost::poll_quarantine)?;
    assert!(!again.remaining && again.driver.is_none());
    fixture.finish()
}
