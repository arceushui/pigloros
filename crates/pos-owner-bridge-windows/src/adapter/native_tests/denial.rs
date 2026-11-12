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
use pos_owner_bridge::{BridgeError, CleanupStore, LoopbackPort, QuarantineCode, SystemClock};
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
    lose_after_receipt: bool,
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
            lose_after_receipt: false,
        })
    }

    fn drive(
        &mut self,
        driver: &mut CeremonyDriver,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            self.trace
                .update("denial-active", &self.surface, driver, &self.loopback);
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.lose_after_receipt && driver.first_receipt_at().is_some() {
                self.lose_after_receipt = false;
                self.surface.controller_lost();
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("denial driver finished without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn retire(&mut self, driver: CeremonyDriver, result: Result<Verified, BridgeError>) -> bool {
        let trace = &mut self.trace;
        super::retirement::retire(
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
            driver,
            result,
            |surface, driver, loopback| {
                trace.update("denial-quarantine", surface, driver, loopback);
            },
        )
    }

    fn attempt(
        &mut self,
        driver: &mut CeremonyDriver,
    ) -> (
        Result<Verified, BridgeError>,
        Option<Box<dyn std::error::Error>>,
    ) {
        let attempt = catch_unwind(AssertUnwindSafe(|| self.drive(driver)));
        let failure = match attempt {
            Ok(Ok(result)) => return (result, None),
            Ok(Err(error)) => error,
            Err(_) => "native denial driver panicked".into(),
        };
        let result = readiness::cancel_driver(
            driver,
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
        );
        (result, Some(failure))
    }

    fn finish(mut self) -> TestResult {
        assert!(self.store.records()?.is_empty());
        assert!(self.store.folders()?.is_empty());
        drop(self.surface);
        Rc::get_mut(&mut self.factory)
            .ok_or("native fixture factory still shared")?
            .stop()?;
        Ok(())
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
    // side effects: callback, one driver retry, one keeper retry. Repeated Close
    // and event draining in one progression cannot add retries. The keeper's
    // later normal STA progression performs actual Stop/Complete.
    let (result, failure) = fixture.attempt(&mut driver);
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
    fixture.finish()
}

pub(super) fn run_control(runtime: &Path, root: &Path) -> TestResult {
    let mut fixture = Fixture::new(runtime, root, Some(FixtureProfile::PopupReceipt))?;
    let _fault = super::controls::Fault::new(
        crate::EventKind::NewWindow,
        crate::ControlFault::RetryDenial,
    );
    let started = Instant::now();
    fixture.trace = Trace::new(0x28, started);
    fixture
        .surface
        .set_deadline(started + Duration::from_secs(15));
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([0x28; 16]), started)?;
    let (result, failure) = fixture.attempt(&mut driver);
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
    assert_eq!(observations[0].attempts, 2);
    assert_eq!(observations[0].completions, 0);
    assert!(!observations[0].retired);
    let retired = crate::Native::control_observations();
    assert_eq!(retired.len(), 1);
    assert_eq!(retired[0].attempts, 4);
    assert_eq!(retired[0].readback, Some(true));
    assert_eq!(retired[0].completions, 1);
    assert!(retired[0].retired);
    assert_eq!(fixture.loopback.served().count, 1);
    fixture.finish()
}

struct ProcessObservations;

impl ProcessObservations {
    fn new() -> Self {
        crate::Native::reset_process_failure_observations();
        Self
    }
}

impl Drop for ProcessObservations {
    fn drop(&mut self) {
        crate::Native::reset_process_failure_observations();
    }
}

pub(super) fn run_renderer(runtime: &Path, root: &Path) -> TestResult {
    for (value, profile, control) in [
        (0x29, FixtureProfile::ReadOnlyControl, true),
        (0x2a, FixtureProfile::ReadOnlyWrite, false),
    ] {
        let _observations = ProcessObservations::new();
        let case_root = root.join(format!("renderer-{value}"));
        crate::create_private_directory(&case_root)?;
        let mut fixture = Fixture::new(runtime, &case_root, Some(profile))?;
        fixture.lose_after_receipt = control;
        let started = Instant::now();
        fixture.trace = Trace::new(u64::from(value), started);
        fixture
            .surface
            .set_deadline(started + Duration::from_secs(15));
        let mut driver = readiness::new_driver(CeremonyId::from_bytes([value; 16]), started)?;
        let (result, failure) = fixture.attempt(&mut driver);
        let error = result.as_ref().err().copied();
        let request_clear = driver.request_clear();
        let posts = driver.posts();
        let receipt = driver.first_receipt_at();
        let quarantined = fixture.retire(driver, result);
        if let Some(failure) = failure {
            return Err(failure);
        }
        assert!(
            !quarantined,
            "this case requires timely ordinary retirement"
        );
        assert!(request_clear);
        assert_eq!(
            error,
            Some(BridgeError::Lifecycle(if control {
                pos_owner_bridge::LifecycleCode::ControllerLost
            } else {
                pos_owner_bridge::LifecycleCode::RendererFailed
            }))
        );
        let observed = crate::Native::process_failure_observations();
        if control {
            assert!(observed.is_empty());
            assert!(receipt.is_some());
            assert!(crate::Native::renderer_state_observations().is_empty());
        } else {
            assert_eq!(observed, [Some(true)]);
            assert_eq!(
                crate::Native::renderer_state_observations(),
                [crate::RendererStateObservation {
                    generation: Some(1),
                    reply_state: Some(1),
                    record_count: Some(1),
                }]
            );
        }
        assert_eq!(posts, 1);
        assert_eq!(fixture.loopback.served().count, 1);
        fixture.finish()?;
    }
    Ok(())
}

pub(super) fn run_delivery(runtime: &Path, root: &Path) -> TestResult {
    for (value, profile, minimum_posts) in [
        (0x2b, FixtureProfile::Pending, 1),
        (0x2c, FixtureProfile::DuplicateRequest, 2),
        (0x2d, FixtureProfile::InterleavedPair, 2),
        (0x2e, FixtureProfile::DelayedDelivery, 3),
    ] {
        let _observations = ProcessObservations::new();
        let case_root = root.join(format!("delivery-{value}"));
        crate::create_private_directory(&case_root)?;
        let mut fixture = Fixture::new(runtime, &case_root, Some(profile))?;
        fixture.lose_after_receipt = true;
        let started = Instant::now();
        fixture.trace = Trace::new(u64::from(value), started);
        let deadline = started + Duration::from_secs(15);
        fixture.surface.set_deadline(deadline);
        let mut driver = readiness::new_driver(CeremonyId::from_bytes([value; 16]), started)?;
        let (result, failure) = fixture.attempt(&mut driver);
        let error = result.as_ref().err().copied();
        let posts = driver.posts();
        let receipt = driver.first_receipt_at();
        let request_clear = driver.request_clear();
        let quarantined = fixture.retire(driver, result);
        if let Some(failure) = failure {
            return Err(failure);
        }
        assert!(
            !quarantined,
            "delivery case requires timely ordinary retirement"
        );
        assert_eq!(
            error,
            Some(BridgeError::Lifecycle(
                pos_owner_bridge::LifecycleCode::ControllerLost
            ))
        );
        assert!(receipt.is_some_and(|received| received < deadline));
        if profile == FixtureProfile::Pending {
            assert_eq!(posts, 1);
        } else {
            // An accepted receipt from the intentionally rejected/retired first
            // pair would finish before these required reposts and fail the case.
            assert!(posts >= minimum_posts, "{profile:?}: posts={posts}");
        }
        assert!(request_clear);
        assert!(crate::Native::process_failure_observations().is_empty());
        assert_eq!(fixture.loopback.served().count, 1);
        fixture.finish()?;
    }
    Ok(())
}

#[cfg(test)]
mod model_tests {
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Instant;

    use pos_owner_bridge::fake::clock::FakeClock;
    use pos_owner_bridge::listener::FixtureProfile;
    use pos_owner_bridge::{CleanupStore as _, SystemClock};
    use pos_owner_bridge_codec::CeremonyId;

    use super::{
        readiness, Fixture, SharedLoopback, Surface, TestResult, Trace, WindowsCleanupStore,
    };
    use crate::adapter::native_tests::FixtureRoot;
    use crate::adapter::surface::tests::native::{Creation, Factory};
    use crate::adapter::surface::tests::Runtime;
    use crate::NativeFactory;

    #[test]
    fn modeled_denial_attempt_preserves_errors_after_owner_retirement() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        for (fault, expected) in [
            ("pump", "Sta: CallFailed"),
            ("panic_pump", "native denial driver panicked"),
            ("already_done", "denial driver finished without result"),
        ] {
            let result = FixtureRoot::new().map(|root| {
                let model = Factory::new(Creation::Ready, FakeClock::start());
                model
                    .failure
                    .set((fault != "already_done").then_some(fault));
                let factory: Rc<dyn NativeFactory> = Rc::new(Rc::clone(&model));
                let result = WindowsCleanupStore::open(root.0.clone()).map(|store| {
                    let result =
                        SharedLoopback::start_fixture(FixtureProfile::Pending).map(|loopback| {
                            let result = Surface::new(
                                Rc::clone(&factory),
                                Arc::new(Runtime(root.0.clone())),
                                root.0.clone(),
                                Box::new(loopback.clone()),
                                Box::new(store.clone()),
                                Box::new(SystemClock),
                            )
                            .map_err(pos_owner_bridge::SurfaceError::error)
                            .map(|surface| {
                                let mut fixture = Fixture {
                                    surface,
                                    loopback,
                                    store,
                                    factory,
                                    trace: Trace::new(240, Instant::now()),
                                    lose_after_receipt: false,
                                };
                                let started = Instant::now();
                                fixture.surface.set_deadline(
                                    started + pos_owner_bridge::ceremony::timing::READINESS,
                                );
                                let result = readiness::new_driver(
                                    CeremonyId::from_bytes([240; 16]),
                                    started,
                                )
                                .map(|mut driver| {
                                    if fault == "already_done" {
                                        let cancelled = readiness::cancel_driver(
                                            &mut driver,
                                            &mut fixture.surface,
                                            &mut fixture.loopback,
                                            &mut fixture.store,
                                        );
                                        assert_eq!(
                                            cancelled.err(),
                                            Some(pos_owner_bridge::BridgeError::Lifecycle(
                                                pos_owner_bridge::LifecycleCode::ControllerLost,
                                            ))
                                        );
                                    }
                                    let (result, failure) = fixture.attempt(&mut driver);
                                    let error = failure.map(|error| error.to_string());
                                    let request_clear = driver.request_clear();
                                    let quarantined = fixture.retire(driver, result);
                                    assert!(!quarantined, "{fault}");
                                    assert!(
                                        error
                                            .as_deref()
                                            .is_some_and(|value| value.starts_with(expected)),
                                        "{fault}"
                                    );
                                    assert!(request_clear);
                                    assert!(fixture.surface.idle());
                                    assert!(fixture
                                        .store
                                        .records()
                                        .is_ok_and(|records| records.is_empty()));
                                    let calls = model.calls.borrow();
                                    assert!(!calls.contains(&"navigate"));
                                    assert!(!calls.contains(&"create_buffers"));
                                    assert!(!calls.contains(&"post"));
                                    if fault == "already_done" {
                                        assert!(!calls.contains(&"create_environment"));
                                    } else {
                                        assert!(calls.contains(&"drop_environment"));
                                    }
                                    drop(calls);
                                    drop(fixture);
                                });
                                assert!(result.is_ok(), "driver creation: {result:?}");
                            });
                            assert!(result.is_ok(), "surface creation: {result:?}");
                        });
                    assert!(result.is_ok(), "loopback creation: {result:?}");
                });
                assert!(result.is_ok(), "store creation: {result:?}");
                assert!(root.remove().is_ok());
            });
            assert!(result.is_ok(), "fixture root: {result:?}");
        }
        Ok(())
    }
}
