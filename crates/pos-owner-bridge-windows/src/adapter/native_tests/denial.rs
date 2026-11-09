#![cfg(windows)]
#![forbid(unsafe_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step};
use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::listener::FixtureProfile;
use pos_owner_bridge::{
    BridgeError, CleanupStore, LoopbackPort, QuarantineCode, QuarantineKeeper, SystemClock,
};
use pos_owner_bridge_codec::CeremonyId;

use super::{readiness, trace::Trace, ResourceProbeGuard, TestResult};
use crate::adapter::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use crate::NativeFactory;

struct Fixture {
    surface: Surface,
    loopback: SharedLoopback,
    store: WindowsCleanupStore,
    factory: Rc<dyn NativeFactory>,
    trace: Trace,
}

impl Fixture {
    fn new(
        runtime: &Path,
        root: &Path,
        profile: Option<FixtureProfile>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Arc::new(crate::verify_fixed_runtime(runtime, root)?);
        let factory: Rc<dyn NativeFactory> = Rc::new(crate::Native::owner_factory()?);
        let store = WindowsCleanupStore::open(root.to_path_buf())?;
        let loopback = match profile {
            Some(profile) => SharedLoopback::start_fixture(profile)?,
            None => SharedLoopback::start()?,
        };
        let surface = Surface::new(
            Rc::clone(&factory),
            runtime,
            root.to_path_buf(),
            Box::new(loopback.clone()),
            Box::new(store.clone()),
            Box::new(SystemClock),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        Ok(Self {
            surface,
            loopback,
            store,
            factory,
            trace: Trace::new(0x27, Instant::now()),
        })
    }

    fn drive(
        &mut self,
        driver: &mut CeremonyDriver,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            self.trace
                .update("denial-active", &self.surface, driver, &self.loopback);
            match driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            )) {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("denial driver finished without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn retire(&mut self, driver: CeremonyDriver, result: Result<Verified, BridgeError>) -> bool {
        let mut keeper = QuarantineKeeper::new();
        let reply = keeper.finish(driver, result);
        let was_quarantined = reply.driver.is_none();
        let mut quarantined = was_quarantined;
        self.surface.abandon_opening();
        while quarantined || !self.surface.idle() {
            if quarantined {
                quarantined = keeper
                    .poll(|driver| {
                        self.trace.update(
                            "denial-quarantine",
                            &self.surface,
                            driver,
                            &self.loopback,
                        );
                        driver.poll_cleanup(&mut readiness::env(
                            &mut self.surface,
                            &mut self.loopback,
                            &mut self.store,
                        ))
                    })
                    .remaining;
            } else {
                let _retired_or_retained = self.surface.poll_failed_open();
            }
            if quarantined || !self.surface.idle() {
                readiness::pump_retaining(&self.surface);
            }
        }
        was_quarantined
    }
}

pub(super) fn run(runtime: &Path, root: &Path) -> TestResult {
    let mut fixture = Fixture::new(runtime, root, None)?;
    let _mode = ResourceProbeGuard::new(crate::ResourceDenialFixture::DriverRetry);
    let started = Instant::now();
    fixture.trace = Trace::new(0x27, started);
    fixture
        .surface
        .set_deadline(started + Duration::from_secs(15));
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([0x27; 16]), started)?;
    // A modeled policy denial and failed SetResponse run in the real callback.
    // Real GetDeferral holds it while the first three Stop attempts fail without
    // side effects: callback, driver unsubscribe, driver Close. The keeper's
    // normal Surface.take_event continuation performs actual Stop/Complete.
    let attempt = catch_unwind(AssertUnwindSafe(|| fixture.drive(&mut driver)));
    let (result, failure) = match attempt {
        Ok(Ok(result)) => (result, None),
        Ok(Err(error)) => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            Some(error),
        ),
        Err(_) => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            Some("denial driver panicked".into()),
        ),
    };
    let error = result.as_ref().err().copied();
    let records = fixture.store.records();
    let received = fixture.loopback.received_request_count();
    let completions = crate::Native::resource_deferral_completion_attempts();
    let quarantined = fixture.retire(driver, result);
    // Assert only after native retirement, including every error/unwind path.
    if let Some(failure) = failure {
        return Err(failure);
    }
    assert_eq!(
        error,
        Some(BridgeError::Quarantine(
            QuarantineCode::ControllerCloseFailed
        ))
    );
    assert!(quarantined);
    assert_eq!(records?.len(), 1);
    assert_eq!(received?, 0);
    assert_eq!(completions, 0);
    assert_eq!(crate::Native::resource_deferral_completion_attempts(), 1);
    assert_eq!(fixture.loopback.received_request_count()?, 0);
    assert_eq!(fixture.loopback.served().count, 0);
    assert!(fixture.store.records()?.is_empty());
    assert!(fixture.store.folders()?.is_empty());
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("denial factory still shared")?
        .stop()?;
    Ok(())
}

pub(super) fn run_control(runtime: &Path, root: &Path) -> TestResult {
    let mut fixture = Fixture::new(runtime, root, Some(FixtureProfile::PopupReceipt))?;
    let _fault = super::controls::Fault::new(
        crate::EventKind::NewWindow,
        crate::ControlFault::RetryDenial,
    );
    let started = Instant::now();
    fixture
        .surface
        .set_deadline(started + Duration::from_secs(15));
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([0x28; 16]), started)?;
    let attempt = catch_unwind(AssertUnwindSafe(|| fixture.drive(&mut driver)));
    let (result, failure) = match attempt {
        Ok(Ok(result)) => (result, None),
        Ok(Err(error)) => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            Some(error),
        ),
        Err(_) => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            Some("control driver panicked".into()),
        ),
    };
    let error = result.as_ref().err().copied();
    let records = fixture.store.records();
    let observations = crate::Native::control_observations();
    let request_clear = driver.request_clear();
    let quarantined = fixture.retire(driver, result);
    if let Some(failure) = failure {
        return Err(failure);
    }
    assert_eq!(
        error,
        Some(BridgeError::Quarantine(
            QuarantineCode::ControllerCloseFailed
        ))
    );
    assert!(quarantined);
    assert!(request_clear);
    assert_eq!(records?.len(), 1);
    assert_eq!(observations.len(), 1);
    assert!(observations[0].deferred);
    assert_eq!(observations[0].attempts, 3);
    assert_eq!(observations[0].completions, 0);
    assert!(!observations[0].retired);
    let retired = crate::Native::control_observations();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].attempts, 4);
    assert_eq!(retired[0].readback, Some(true));
    assert_eq!(retired[0].completions, 1);
    assert!(retired[0].retired);
    assert_eq!(fixture.loopback.served().count, 1);
    assert!(fixture.store.records()?.is_empty());
    assert!(fixture.store.folders()?.is_empty());
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("control factory still shared")?
        .stop()?;
    Ok(())
}
