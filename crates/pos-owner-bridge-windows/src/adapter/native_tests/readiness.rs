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
use pos_owner_bridge::{
    BridgeError, CleanupStore, LifecycleCode, OwnerWebSurface, QuarantineKeeper, SystemClock,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ControlState, CoseEs256PublicKey, OwnerUserHandle, PrfInput,
    WebAuthnChallenge,
};

use super::super::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use super::foreground::{Foreground, Ticket};
use super::trace::Trace;
use super::TestResult;
use crate::{NativeFactory, NativePulse, StaPump};

const WORKERS: usize = 4;
const RUNS_PER_WORKER: usize = 250;

pub(super) fn run(runtime_path: &Path, root: &Path) -> TestResult {
    let loopback = SharedLoopback::start()?;
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
    drop(surface);
    assert!(store.records()?.is_empty());
    assert!(store.folders()?.is_empty());
    drop(store);
    let mut factory = Rc::try_unwrap(factory).map_err(|_| "readiness factory still shared")?;
    factory.stop()?;
    outcome
}

fn run_ceremony(
    surface: &mut Surface,
    loopback: &mut SharedLoopback,
    store: &mut WindowsCleanupStore,
    foreground: &Foreground,
    id: CeremonyId,
    number: u64,
) -> TestResult {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    surface.set_deadline(deadline);
    let mut driver = new_driver(id, started)?;
    let mut trace = Trace::new(number, started);
    let mut visible = Some(acquire_foreground(
        surface, foreground, deadline, &driver, &mut trace, number,
    )?);
    let mut receipt = None;
    // Keep both the driver and its native owners outside the unwind boundary.
    // An assertion failure must enter the same release/exit path as an error.
    let attempt = catch_unwind(AssertUnwindSafe(
        || -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
            loop {
                trace.update("active", surface, &driver);
                if receipt.is_none() && driver.posts() > 0 && !driver.request_clear() {
                    let state = surface
                        .reply_load_state()
                        .map_err(pos_owner_bridge::SurfaceError::error)?;
                    if state != ControlState::Empty as u32 {
                        receipt = Some(Instant::now());
                        // Controlled lifecycle cancellation after actual packaged-page
                        // receipt; this does not claim an authenticator result.
                        surface.controller_lost();
                        drop(visible.take());
                    }
                }
                match driver.step(&mut env(surface, loopback, store)) {
                    Step::Finished(result) => return Ok(result),
                    Step::Done => return Err("readiness driver finished without a result".into()),
                    Step::Pending => pump(surface)?,
                }
            }
        },
    ));
    drop(visible);
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
    trace.update("caller-complete", surface, &driver);
    let mut keeper = QuarantineKeeper::new();
    let reply = keeper.finish(driver, result);
    let mut quarantined = reply.driver.is_none();
    surface.abandon_opening();
    // Caller timeouts do not authorize destruction. Keep the exact environment,
    // exit handler, record, driver and STA until actual retirement succeeds.
    while quarantined || !surface.idle() {
        if quarantined {
            let poll = keeper.poll(|driver| {
                trace.update("quarantine", surface, driver);
                driver.poll_cleanup(&mut env(surface, loopback, store))
            });
            quarantined = poll.remaining;
        } else {
            let _retired_or_retained = surface.poll_failed_open();
        }
        if quarantined || !surface.idle() {
            pump_retaining(surface);
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if receipt.is_none_or(|received| received >= deadline)
        || result_error != Some(BridgeError::Lifecycle(LifecycleCode::ControllerLost))
    {
        return Err(format!("packaged Get readiness/cancellation failed: receipt={receipt:?}, result={result_error:?}").into());
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
    deadline: Instant,
    driver: &CeremonyDriver,
    trace: &mut Trace,
    number: u64,
) -> Result<Ticket<'a>, Box<dyn std::error::Error>> {
    let ticket = foreground.request(number)?;
    loop {
        trace.update("foreground", surface, driver);
        if ticket.is_next()? {
            return Ok(ticket);
        }
        if Instant::now() >= deadline {
            return Err("readiness expired waiting for the foreground coordination gate".into());
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
