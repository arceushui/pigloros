#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step, StepEnv};
use pos_owner_bridge::ceremony::plan::{CeremonyPlan, StoredGet, Verified};
use pos_owner_bridge::fake::signer::FIXTURE_COSE_KEY;
use pos_owner_bridge::{BridgeError, CleanupStore, LifecycleCode, SystemClock};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerUserHandle, PrfInput, WebAuthnChallenge,
};

use super::super::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use super::foreground::{Foreground, Ticket};
use super::trace::{worker_stage, Trace};
use super::{retirement, TestResult};
use crate::{NativeFactory, NativePulse, StaPump};

const WORKERS: usize = 4;
const RUNS_PER_WORKER: usize = 250;

pub(super) fn run(runtime_path: &Path, root: &Path) -> TestResult {
    let loopback =
        SharedLoopback::start_fixture(pos_owner_bridge::listener::FixtureProfile::Pending)?;
    let foreground = Arc::new(Foreground::default());
    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let path = runtime_path.to_path_buf();
        let root = root.join(format!("readiness-{worker}"));
        let loopback = loopback.clone();
        let foreground = Arc::clone(&foreground);
        workers.push(thread::spawn(move || {
            run_worker(&path, root, loopback, &foreground, worker)
                .map_err(|error| error.to_string())
        }));
    }
    // Every creating STA retires its accepted owners before its join completes.
    let results: Vec<_> = workers.into_iter().map(thread::JoinHandle::join).collect();
    let mut reports = Vec::new();
    for (worker, result) in results.into_iter().enumerate() {
        let result =
            result.unwrap_or_else(|_| Err(format!("readiness STA worker {worker} panicked")));
        writeln!(
            std::io::stderr(),
            "NATIVE_READINESS worker={worker} result={result:?}"
        )?;
        reports.push(result);
    }
    let mut completed = 0;
    for result in reports {
        completed += result?;
    }
    assert_eq!(completed, 1_000);
    Ok(())
}

fn run_worker(
    runtime_path: &Path,
    root: PathBuf,
    mut loopback: SharedLoopback,
    foreground: &Foreground,
    worker: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    crate::create_private_directory(&root)?;
    let runtime = Arc::new(crate::verify_fixed_runtime(runtime_path, &root)?);
    let factory = Rc::new(crate::Native::owner_factory()?);
    let shared_factory: Rc<dyn NativeFactory> = factory.clone();
    let mut store = WindowsCleanupStore::open(root.clone())?;
    let mut surface = Surface::new(
        shared_factory,
        runtime,
        root,
        Box::new(loopback.clone()),
        Box::new(store.clone()),
        Box::new(SystemClock),
    )
    .map_err(pos_owner_bridge::SurfaceError::error)?;
    let mut outcome = Ok(RUNS_PER_WORKER);
    for iteration in 0..RUNS_PER_WORKER {
        let number = u64::try_from(worker * RUNS_PER_WORKER + iteration + 1)?;
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&number.to_le_bytes());
        let started = Instant::now();
        let attempt = run_ceremony(
            &mut surface,
            &mut loopback,
            &mut store,
            foreground,
            CeremonyId::from_bytes(bytes),
            number,
        );
        if let Err(error) = attempt {
            outcome = Err(format!(
                "native readiness worker {worker} case {number}, {iteration} completed, elapsed={:?}: {error}",
                started.elapsed()
            ).into());
            break;
        }
    }
    // run_ceremony also retires failed and panicking cases before returning.
    worker_stage(worker, "dropping-surface");
    drop(surface);
    worker_stage(worker, "surface-dropped");
    assert!(store.records()?.is_empty());
    assert!(store.folders()?.is_empty());
    worker_stage(worker, "store-checked");
    drop(store);
    worker_stage(worker, "store-dropped");
    let mut factory = Rc::try_unwrap(factory).map_err(|_| "readiness factory still shared")?;
    factory.stop()?;
    worker_stage(worker, "timer-stopped");
    drop(factory);
    worker_stage(worker, "apartment-released");
    outcome
}

// Constant-memory observations of existing driver and STA pump calls.
#[derive(Default)]
struct ProgressBand {
    step_entered: u32,
    step_returned: u32,
    pump_entered: u32,
    pump_returned: u32,
    max_step: Duration,
    max_pump: Duration,
    max_interstep: Duration,
    last_step_return: Option<Instant>,
}

impl ProgressBand {
    fn enter_step(&mut self) -> Instant {
        let now = Instant::now();
        self.step_entered = self.step_entered.saturating_add(1);
        if let Some(last) = self.last_step_return {
            self.max_interstep = self.max_interstep.max(now.saturating_duration_since(last));
        }
        now
    }

    fn return_step(&mut self, started: Instant) {
        let now = Instant::now();
        self.step_returned = self.step_returned.saturating_add(1);
        self.max_step = self.max_step.max(now.saturating_duration_since(started));
        self.last_step_return = Some(now);
    }

    fn enter_pump(&mut self) -> Instant {
        self.pump_entered = self.pump_entered.saturating_add(1);
        Instant::now()
    }

    fn return_pump(&mut self, started: Instant) {
        self.pump_returned = self.pump_returned.saturating_add(1);
        self.max_pump = self.max_pump.max(started.elapsed());
    }
}

#[derive(Default)]
struct ProgressTiming {
    before_receipt: ProgressBand,
    after_receipt: ProgressBand,
}

impl ProgressTiming {
    const fn band(&mut self, received: bool) -> &mut ProgressBand {
        if received {
            &mut self.after_receipt
        } else {
            &mut self.before_receipt
        }
    }

    fn report(&self, case: u64) {
        let before = &self.before_receipt;
        let after = &self.after_receipt;
        let _logged = writeln!(std::io::stderr(),
            "NATIVE_G3_CALL_TIMING case={case} before_step_entered={} before_step_returned={} before_pump_entered={} before_pump_returned={} before_max_step={:?} before_max_pump={:?} before_max_interstep={:?} after_step_entered={} after_step_returned={} after_pump_entered={} after_pump_returned={} after_max_step={:?} after_max_pump={:?} after_max_interstep={:?}",
            before.step_entered, before.step_returned, before.pump_entered, before.pump_returned,
            before.max_step, before.max_pump, before.max_interstep,
            after.step_entered, after.step_returned, after.pump_entered, after.pump_returned,
            after.max_step, after.max_pump, after.max_interstep);
    }
}

fn run_ceremony(
    surface: &mut Surface,
    loopback: &mut SharedLoopback,
    store: &mut WindowsCleanupStore,
    foreground: &Foreground,
    id: CeremonyId,
    number: u64,
) -> TestResult {
    // Coordinate independent test STAs before constructing this synthetic plan.
    // Once T0 exists it is never reset; all native opening/foreground work and
    // receipt still share the original fifteen-second ceremony deadline.
    // Match product admission: do not start another ceremony while this one's
    // cancellation or browser retirement is unresolved, even after receipt.
    let _visible = acquire_foreground(surface, foreground, number)?;
    let started = Instant::now();
    surface.begin_readiness_timing(number, started);
    crate::Native::readiness_navigation_case(Some((number, started)));
    let deadline = started + Duration::from_secs(15);
    surface.set_deadline(deadline);
    let mut driver = new_driver(id, started)?;
    let mut trace = Trace::new(number, started);
    let mut receipt = None;
    let mut timing = ProgressTiming::default();
    // Keep both the driver and its native owners outside the unwind boundary.
    // An assertion failure must enter the same release/exit path as an error.
    let attempt = catch_unwind(AssertUnwindSafe(
        || -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
            loop {
                trace.update("active", surface, &driver, loopback);
                let step_started = timing.band(receipt.is_some()).enter_step();
                let step = driver.step(&mut env(surface, loopback, store));
                timing.band(receipt.is_some()).return_step(step_started);
                if receipt.is_none() {
                    if let Some(observed) = driver.first_receipt_at() {
                        // Observe the driver's accepted page advance, including
                        // one consumed/wiped within that same step. Host release
                        // states and invalid values cannot satisfy this oracle.
                        receipt = Some(observed);
                        // Include the boundary between this return and the first
                        // step entered after observing the receipt.
                        timing.after_receipt.last_step_return =
                            timing.before_receipt.last_step_return;
                        surface.controller_lost();
                    }
                }
                match step {
                    Step::Finished(result) => return Ok(result),
                    Step::Done => return Err("readiness driver finished without a result".into()),
                    Step::Pending => {
                        let pump_started = timing.band(receipt.is_some()).enter_pump();
                        let pumped = pump(surface);
                        timing.band(receipt.is_some()).return_pump(pump_started);
                        pumped?;
                    }
                }
            }
        },
    ));
    timing.report(number);
    let (result, failure) = match attempt {
        Ok(Ok(result)) => (result, None),
        Ok(Err(error)) => (
            cancel_driver(&mut driver, surface, loopback, store),
            Some(error),
        ),
        Err(_) => (
            cancel_driver(&mut driver, surface, loopback, store),
            Some("native readiness case panicked".into()),
        ),
    };
    let result_error = result.as_ref().err().copied();
    trace.update("caller-complete", surface, &driver, loopback);
    retirement::retire(
        surface,
        loopback,
        store,
        driver,
        result,
        |surface, driver, loopback| {
            trace.update("quarantine", surface, driver, loopback);
        },
    );
    surface.report_readiness_timing();
    let resource = crate::Native::readiness_resource_snapshot();
    let _logged = writeln!(std::io::stderr(),
        "NATIVE_G3_RESOURCE_SNAPSHOT case={number} fields=(captured_case,entries,overflow,subscriptions) snapshot={resource:?}");
    crate::Native::readiness_navigation_case(None);
    readiness_verdict(failure, receipt, deadline, result_error, resource)
}

// Pure verdict over observations collected after the real retirement path.
fn readiness_verdict(
    failure: Option<Box<dyn std::error::Error>>,
    receipt: Option<Instant>,
    deadline: Instant,
    result_error: Option<BridgeError>,
    resource: Option<(Option<u64>, u8, bool, u8)>,
) -> TestResult {
    if let Some(error) = failure {
        return Err(format!("{error}; resource snapshot={resource:?}").into());
    }
    if receipt.is_none_or(|received| received >= deadline)
        || !matches!(
            result_error,
            Some(BridgeError::Lifecycle(
                LifecycleCode::ControllerLost | LifecycleCode::ClientFailed
            ))
        )
    {
        return Err(format!("packaged Get readiness/cancellation failed: receipt={receipt:?}, result={result_error:?}, resource snapshot={resource:?}").into());
    }
    Ok(())
}

pub(super) fn new_driver(
    id: CeremonyId,
    started: Instant,
) -> Result<CeremonyDriver, Box<dyn std::error::Error>> {
    let stored = StoredGet::new(
        vec![0x80, 0x81],
        OwnerUserHandle::from_bytes([4; 32]),
        CoseEs256PublicKey::from_canonical_encoding(&FIXTURE_COSE_KEY)
            .map_err(|error| error.to_string())?,
        false,
        false,
        0,
    );
    let plan = CeremonyPlan::for_test(
        CeremonyKind::Get,
        id,
        WebAuthnChallenge::from_bytes([2; 32]),
        OwnerUserHandle::from_bytes([4; 32]),
        PrfInput::from_bytes([3; 32]),
        started,
    )
    .with_stored(Some(stored));
    Ok(CeremonyDriver::for_test(plan))
}

pub(super) fn env<'a>(
    surface: &'a mut Surface,
    loopback: &'a mut SharedLoopback,
    store: &'a mut WindowsCleanupStore,
) -> StepEnv<'a> {
    StepEnv {
        surface,
        clock: &SystemClock,
        loopback,
        store,
    }
}

pub(super) fn cancel_driver(
    driver: &mut CeremonyDriver,
    surface: &mut Surface,
    loopback: &mut SharedLoopback,
    store: &mut WindowsCleanupStore,
) -> Result<Verified, BridgeError> {
    surface.controller_lost();
    loop {
        match driver.step(&mut env(surface, loopback, store)) {
            Step::Finished(result) => return result,
            Step::Done => return Err(BridgeError::Lifecycle(LifecycleCode::ControllerLost)),
            Step::Pending => pump_retaining(surface),
        }
    }
}

fn acquire_foreground<'a>(
    surface: &Surface,
    foreground: &'a Foreground,
    number: u64,
) -> Result<Ticket<'a>, Box<dyn std::error::Error>> {
    let ticket = foreground.request(number, Instant::now())?;
    let mut trace = Trace::new(number, Instant::now());
    loop {
        trace.queued(surface);
        if ticket.is_next(Instant::now())? {
            return Ok(ticket);
        }
        pump(surface)?;
    }
}

pub(super) fn pump(surface: &Surface) -> TestResult {
    if surface.pump()? == NativePulse::Quit {
        return Err("native readiness STA received quit".into());
    }
    Ok(())
}

pub(super) fn pump_retaining(surface: &Surface) {
    if pump(surface).is_err() {
        // Match the host's retention behavior after a pump failure. No owner is
        // discarded merely because the event loop is temporarily unavailable.
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Instant;

    use pos_owner_bridge::fake::clock::FakeClock;
    use pos_owner_bridge::listener::FixtureProfile;
    use pos_owner_bridge::{CleanupStore, SystemClock};
    use pos_owner_bridge_codec::CeremonyId;

    use super::{
        run_ceremony, Foreground, SharedLoopback, Surface, TestResult, WindowsCleanupStore,
    };
    use crate::adapter::native_tests::FixtureRoot;
    use crate::adapter::surface::tests::native::{Creation, Factory};
    use crate::adapter::surface::tests::Runtime;
    use crate::NativeFactory;

    struct QuitTwiceFactory {
        native: Rc<Factory>,
        pulses: std::cell::Cell<u8>,
    }

    impl crate::StaPump for QuitTwiceFactory {
        fn next(&self) -> crate::NativeResult<crate::NativePulse> {
            let count = self.pulses.get();
            self.pulses.set(count.saturating_add(1));
            Ok(if count < 2 {
                crate::NativePulse::Quit
            } else {
                crate::NativePulse::Timer
            })
        }

        fn stop(&mut self) -> crate::NativeResult<()> {
            Ok(())
        }
    }

    impl NativeFactory for QuitTwiceFactory {
        fn session(&self) -> crate::NativeResult<Box<dyn crate::NativeOperations>> {
            self.native.session()
        }
    }

    #[test]
    fn modeled_quit_retains_pending_owners_and_cancel_done_is_stable() -> TestResult {
        use pos_owner_bridge::OwnerWebSurface as _;

        let _port = crate::Native::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let model = Factory::new(Creation::Pending, FakeClock::start());
        let scripted = Rc::new(QuitTwiceFactory {
            native: Rc::clone(&model),
            pulses: std::cell::Cell::new(0),
        });
        let factory: Rc<dyn NativeFactory> = scripted.clone();
        let mut store = WindowsCleanupStore::open(root.0.clone())?;
        let mut loopback = SharedLoopback::start_fixture(FixtureProfile::Pending)?;
        let mut surface = Surface::new(
            Rc::clone(&factory),
            Arc::new(Runtime(root.0.clone())),
            root.0.clone(),
            Box::new(loopback.clone()),
            Box::new(store.clone()),
            Box::new(SystemClock),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        let started = Instant::now();
        surface.set_deadline(started + pos_owner_bridge::ceremony::timing::READINESS);
        let ceremony = CeremonyId::from_bytes([239; 16]);
        let spec = pos_owner_bridge::SurfaceSpec {
            ceremony_id: ceremony,
            folder_name: pos_owner_bridge::folder_name(&ceremony),
            owner_window: None,
        };
        assert!(surface.open(&spec).is_pending());
        assert!(surface.open(&spec).is_pending());
        assert!(super::pump(&surface).is_err());
        super::pump_retaining(&surface);
        assert_eq!(scripted.pulses.get(), 2);
        assert!(!surface.idle());
        assert!(surface.recordless_opening_ready());
        assert!(store.records()?.is_empty());
        assert!(!model.calls.borrow().contains(&"unsubscribe_exit"));
        assert!(!model.calls.borrow().contains(&"drop_environment"));
        model.creation.set(Creation::CallbackFailure);
        surface.abandon_opening();
        assert!(surface
            .poll_failed_open()
            .map_err(pos_owner_bridge::SurfaceError::error)?);
        assert!(surface.idle());

        let mut driver = super::new_driver(ceremony, Instant::now())?;
        for _ in 0..2 {
            let error =
                super::cancel_driver(&mut driver, &mut surface, &mut loopback, &mut store).err();
            assert_eq!(
                error,
                Some(pos_owner_bridge::BridgeError::Lifecycle(
                    pos_owner_bridge::LifecycleCode::ControllerLost
                ))
            );
            assert!(driver.request_clear());
        }
        assert!(surface.idle());
        assert!(store.records()?.is_empty());
        drop(surface);
        drop(loopback);
        drop(store);
        drop(factory);
        root.remove()
    }

    #[test]
    fn modeled_readiness_verdict_preserves_deadline_result_and_error_precedence() {
        use pos_owner_bridge::{BridgeError, LifecycleCode, QuarantineCode};
        use std::time::Duration;

        let start = Instant::now();
        let deadline = start + Duration::from_secs(15);
        let before = Some(start + Duration::from_secs(14) + Duration::from_nanos(999_999_999));
        let snapshot = Some((Some(7), 0, false, 1));
        for code in [LifecycleCode::ControllerLost, LifecycleCode::ClientFailed] {
            assert!(super::readiness_verdict(
                None,
                before,
                deadline,
                Some(BridgeError::Lifecycle(code)),
                snapshot
            )
            .is_ok());
        }
        for receipt in [
            None,
            Some(deadline),
            Some(deadline + Duration::from_nanos(1)),
        ] {
            let error = super::readiness_verdict(
                None,
                receipt,
                deadline,
                Some(BridgeError::Lifecycle(LifecycleCode::ControllerLost)),
                snapshot,
            )
            .err()
            .map(|error| error.to_string());
            assert!(error.as_deref().is_some_and(
                |value| value.starts_with("packaged Get readiness/cancellation failed:")
            ));
        }
        for result in [
            None,
            Some(BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout)),
            Some(BridgeError::Quarantine(
                QuarantineCode::ControllerCloseFailed,
            )),
        ] {
            let error = super::readiness_verdict(None, before, deadline, result, snapshot)
                .err()
                .map(|error| error.to_string());
            assert!(error.as_deref().is_some_and(
                |value| value.starts_with("packaged Get readiness/cancellation failed:")
            ));
        }
        let failure: Box<dyn std::error::Error> = "modeled prior failure".into();
        let error = super::readiness_verdict(Some(failure), None, deadline, None, snapshot)
            .err()
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("modeled prior failure; resource snapshot=Some((Some(7), 0, false, 1))")
        );
    }

    #[test]
    fn modeled_readiness_failures_retire_before_reporting_and_release_foreground() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        for (creation, failure, expected) in [
            (Creation::Ready, Some("pump"), "Sta: CallFailed"),
            (
                Creation::Ready,
                Some("panic_pump"),
                "native readiness case panicked",
            ),
            (
                Creation::SynchronousFailure,
                None,
                "packaged Get readiness/cancellation failed",
            ),
        ] {
            let number = 10_240;
            let _logged = writeln!(std::io::stderr(), "NATIVE_READINESS_MODEL case={number} observation=scripted qualified=false expected={expected}");
            let root = FixtureRoot::new()?;
            let model = Factory::new(creation, FakeClock::start());
            model.failure.set(failure);
            let factory: Rc<dyn NativeFactory> = Rc::new(Rc::clone(&model));
            let mut store = WindowsCleanupStore::open(root.0.clone())?;
            let mut loopback = SharedLoopback::start_fixture(FixtureProfile::Pending)?;
            let mut surface = Surface::new(
                Rc::clone(&factory),
                Arc::new(Runtime(root.0.clone())),
                root.0.clone(),
                Box::new(loopback.clone()),
                Box::new(store.clone()),
                Box::new(SystemClock),
            )
            .map_err(pos_owner_bridge::SurfaceError::error)?;
            let foreground = Foreground::default();
            let error = run_ceremony(
                &mut surface,
                &mut loopback,
                &mut store,
                &foreground,
                CeremonyId::from_bytes([240; 16]),
                number,
            )
            .err()
            .map(|error| error.to_string());
            assert!(error
                .as_deref()
                .is_some_and(|error| error.starts_with(expected)));
            assert!(surface.idle());
            assert!(store.records()?.is_empty());
            assert_eq!(store.folders()?.len(), 1);
            let calls = model.calls.borrow();
            let unsubscribe = calls
                .iter()
                .position(|call| *call == "unsubscribe_exit")
                .ok_or("exit handler was not retired")?;
            let released = calls
                .iter()
                .position(|call| *call == "drop_environment")
                .ok_or("environment was not retired")?;
            let destroyed = calls
                .iter()
                .position(|call| *call == "destroy_window")
                .ok_or("window was not retired")?;
            assert!(unsubscribe < released && released < destroyed);
            assert!(!calls.contains(&"navigate"));
            assert!(!calls.contains(&"create_buffers"));
            assert!(!calls.contains(&"post"));
            let next = foreground.request(number + 1, Instant::now())?;
            assert!(next.is_next(Instant::now())?);
            drop(next);
            drop(calls);
            drop(surface);
            drop(loopback);
            drop(store);
            drop(factory);
            root.remove()?;
        }
        Ok(())
    }
}
