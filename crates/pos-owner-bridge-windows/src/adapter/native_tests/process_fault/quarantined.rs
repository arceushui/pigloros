#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::task::Poll;
use std::time::Instant;

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step, StepEnv};
use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::{
    BridgeError, CleanupStore, NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity,
    QuarantineCode, QuarantineKeeper, ReplyImage, RequestImage, SurfaceError, SurfaceEvent,
    SurfaceSpec, SystemClock, UnavailableCode,
};
use pos_owner_bridge_codec::CeremonyId;

use super::{
    check_final_process_failures, competing_spec, native_zeroing_observed, readiness, Fixture,
    FixtureProfile, ProcessFaultMark, ProcessFaultTarget, TestResult, ZeroWitness,
};

// This is a modeled port refusal, never an SDK HRESULT or a native Close claim.
struct RefuseClose<'a> {
    surface: &'a mut super::Surface,
    refused: &'a mut bool,
}

impl OwnerWebSurface for RefuseClose<'_> {
    fn open(&mut self, spec: &SurfaceSpec) -> Poll<Result<ProcessIdentity, SurfaceError>> {
        self.surface.open(spec)
    }
    fn navigate(&mut self) -> Poll<Result<NavigationId, SurfaceError>> {
        self.surface.navigate()
    }
    fn create_and_write(
        &mut self,
        request: &RequestImage,
        header: &[u8; 64],
    ) -> Result<(), SurfaceError> {
        self.surface.create_and_write(request, header)
    }
    fn post(&mut self, guard: &PostGuard) -> Result<(), SurfaceError> {
        self.surface.post(guard)
    }
    fn reply_load_state(&self) -> Result<u32, SurfaceError> {
        self.surface.reply_load_state()
    }
    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool, SurfaceError> {
        self.surface.reply_compare_exchange(current, new)
    }
    fn reply_copy(&self, out: &mut ReplyImage) -> Result<(), SurfaceError> {
        self.surface.reply_copy(out)
    }
    fn zero_close_buffers(&mut self) -> Result<(), SurfaceError> {
        self.surface.zero_close_buffers()
    }
    fn close_controller(&mut self) -> Result<(), SurfaceError> {
        *self.refused = true;
        Err(SurfaceError::new(BridgeError::Unavailable(
            UnavailableCode::InterfaceUnavailable,
        )))
    }
    fn take_event(&mut self) -> Option<SurfaceEvent> {
        self.surface.take_event()
    }
    fn finish(&mut self) -> Result<(), SurfaceError> {
        self.surface.finish()
    }
}

fn drive_to_quarantine(
    fixture: &mut Fixture,
    driver: &mut CeremonyDriver,
    refused: &mut bool,
) -> Result<Verified, BridgeError> {
    loop {
        let step = {
            let mut surface = RefuseClose {
                surface: &mut fixture.surface,
                refused: &mut *refused,
            };
            let mut env = StepEnv {
                surface: &mut surface,
                clock: &SystemClock,
                loopback: &mut fixture.loopback,
                store: &mut fixture.store,
            };
            driver.step(&mut env)
        };
        match step {
            Step::Finished(result) => return result,
            Step::Done => {
                return Err(BridgeError::Unavailable(
                    UnavailableCode::InterfaceUnavailable,
                ))
            }
            Step::Pending => readiness::pump_retaining(&fixture.surface),
        }
    }
}

fn keeper_poll(
    keeper: &mut QuarantineKeeper,
    fixture: &mut Fixture,
) -> pos_owner_bridge::QuarantinePoll {
    keeper.poll(|driver| {
        driver.poll_cleanup(&mut readiness::env(
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        ))
    })
}

fn blocked(keeper: &mut QuarantineKeeper, fixture: &mut Fixture, folder: &Path) -> TestResult {
    let polled = keeper_poll(keeper, fixture);
    if !polled.remaining
        || polled.driver.is_some()
        || !folder.is_dir()
        || !folder.join("quarantine-held").is_file()
        || fixture.store.records()?.len() != 1
        || !matches!(fixture.surface.open(&competing_spec()), Poll::Ready(Err(_)))
        || fixture.store.records()?.len() != 1
        || !folder.is_dir()
    {
        return Err("quarantined owners or held folder were not retained".into());
    }
    Ok(())
}

fn retire_keeper(keeper: &mut QuarantineKeeper, fixture: &mut Fixture) {
    let mut returned = None;
    loop {
        let polled = keeper_poll(keeper, fixture);
        if let Some(driver) = polled.driver {
            returned = Some(driver);
        }
        if !polled.remaining && fixture.surface.idle() {
            break;
        }
        readiness::pump_retaining(&fixture.surface);
    }
    if let Some(driver) = returned {
        drop(driver.into_slots());
    }
}

fn observe_case(
    fixture: &mut Fixture,
    keeper: &mut QuarantineKeeper,
    folder: &Path,
    keeper_held: &std::rc::Rc<std::cell::Cell<bool>>,
    (refused, wiped, observations): (bool, bool, &[crate::NativeZeroObservation]),
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<crate::ProcessExitState, Box<dyn std::error::Error>> {
    let native_wiped = native_zeroing_observed(observations);
    if !refused || !wiped || !native_wiped {
        return Err(format!(
            "quarantine mappings or secrets were not wiped: case={} refused={refused} wiped={wiped} native_wiped={native_wiped} observation_count={} observations={:?}",
            fixture.number,
            observations.len(),
            &observations[..observations.len().min(3)]
        ).into());
    }
    let state = fixture
        .surface
        .quarantined_fault_state()
        .map_err(|()| "quarantined owners not established")?;
    fixture
        .trace
        .borrow_mut()
        .push(ProcessFaultMark::ReachedQuarantined(state));
    if !matches!(fixture.surface.open(&competing_spec()), Poll::Ready(Err(_)))
        || fixture.surface.quarantined_fault_state().ok() != Some(state)
    {
        return Err("competing admission changed quarantined owners".into());
    }
    if inject {
        let seal = crate::FaultSeal {
            trace: std::rc::Rc::clone(&fixture.trace),
            deadline: fixture.deadline,
        };
        fixture.handle = Some(
            fixture
                .surface
                .inject_quarantined_fault(target, seal, std::rc::Rc::clone(keeper_held))
                .map_err(|()| "quarantined target was not validated")?,
        );
        fixture.observe_fault_from(target, ProcessFaultMark::ReachedQuarantined(state))?;
    }
    blocked(keeper, fixture, folder)?;
    if inject && target == ProcessFaultTarget::Browser {
        let name = folder
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or("quarantined folder name unavailable")?;
        // Independently observe the real store's folder refusal; unlike
        // delete_record, remove_folder does not change record provenance.
        if fixture.store.remove_folder(name).is_ok()
            || !folder.join("quarantine-held").is_file()
            || fixture.store.records()?.len() != 1
        {
            return Err("held owned file did not refuse ordinary folder cleanup".into());
        }
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_QUARANTINED case={} second_folder_cleanup=refused record_retained=true",
            fixture.number
        );
    }
    let _logged = writeln!(std::io::stderr(),
        "NATIVE_QUARANTINED case={} target={target:?} inject={inject} modeled_close_refusal=true keeper_remaining=true record_retained=true held_file=true", fixture.number);
    Ok(state)
}

fn run_case(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<crate::ProcessExitState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    let _zero = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let mut refused = false;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        drive_to_quarantine(&mut fixture, &mut driver, &mut refused)
    }));
    let Ok(result) = attempt else {
        let result = readiness::cancel_driver(
            &mut driver,
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        );
        fixture.retire(driver, result, None)?;
        return Err("quarantined drive panicked".into());
    };
    let expected = Err(BridgeError::Quarantine(
        QuarantineCode::ControllerCloseFailed,
    ));
    if result != expected {
        fixture.retire(driver, result, None)?;
        return Err("modeled close refusal did not quarantine".into());
    }
    let wiped = driver.request_clear()
        && driver.prf().iter().all(|byte| *byte == 0)
        && driver.plan_secrets_clear();
    let observations = crate::Native::take_native_zero_observations();
    let folder = root
        .join(format!("process-fault-{number}"))
        .join(pos_owner_bridge::folder_name(&CeremonyId::from_bytes(
            [number; 16],
        )));
    let held_path = folder.join("quarantine-held");
    let held = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&held_path)
    {
        Ok(held) => held,
        Err(error) => {
            let _closed_or_retained = fixture.surface.close_controller();
            fixture.retire(driver, result, None)?;
            return Err(error.into());
        }
    };
    let mut keeper = QuarantineKeeper::new();
    // QuarantineKeeper::finish unconditionally retains a driver for this exact
    // quarantine result; it returns the input result without transformation.
    let _reply = keeper.finish(driver, result);
    let keeper_held = std::rc::Rc::new(std::cell::Cell::new(refused));
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        observe_case(
            &mut fixture,
            &mut keeper,
            &folder,
            &keeper_held,
            (refused, wiped, &observations),
            target,
            inject,
        )
    }))
    .unwrap_or_else(|_| Err("quarantined fixture panicked".into()));
    keeper_held.set(false);
    // Release only the fixture's own file, then perform the ordinary real Close.
    drop(held);
    let closed = fixture.surface.close_controller();
    let close_observation = fixture.surface.initial_close_observation();
    retire_keeper(&mut keeper, &mut fixture);
    drop(fixture.handle.take());
    drop(fixture.surface);
    std::rc::Rc::get_mut(&mut fixture.factory)
        .ok_or("quarantined factory still shared")?
        .stop()?;
    let state = attempt?;
    let _logged = writeln!(
        std::io::stderr(),
        "NATIVE_QUARANTINED_CLOSE case={number} result={closed:?} observation={close_observation:?}"
    );
    check_final_process_failures(inject.then_some(target))?;
    if !fixture.store.records()?.is_empty() || folder.exists() {
        return Err("ordinary quarantine retirement was incomplete".into());
    }
    Ok(state)
}

pub(super) fn run(runtime: &Path, root: &Path) -> TestResult {
    for (number, target) in [
        (0xe0, ProcessFaultTarget::Renderer),
        (0xe2, ProcessFaultTarget::Browser),
    ] {
        let control = run_case(runtime, root, number, target, false)?;
        let fault = run_case(runtime, root, number + 1, target, true)?;
        if control != fault {
            return Err("quarantined control and fault reached different states".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeEvent;

    fn require<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => std::panic::resume_unwind(Box::new(error.to_string())),
        }
    }

    #[test]
    fn modeled_keeper_requires_marker_record_and_blocked_admission_until_cleanup() {
        let _port = crate::Native::fixed_port_fixture();
        let root = require(super::super::FixtureRoot::new());
        let (mut fixture, model) = require(super::super::model_tests::fixture(&root));
        let ceremony = CeremonyId::from_bytes([240; 16]);
        let mut driver = require(readiness::new_driver(ceremony, Instant::now()));
        let mut refused = false;
        let result = drive_to_quarantine(&mut fixture, &mut driver, &mut refused);
        assert_eq!(
            result,
            Err(BridgeError::Quarantine(
                QuarantineCode::ControllerCloseFailed
            ))
        );
        assert!(refused);
        let mut keeper = QuarantineKeeper::new();
        let reply = keeper.finish(driver, result);
        assert!(reply.driver.is_none());
        let folder = root.0.join(pos_owner_bridge::folder_name(&ceremony));
        let marker = folder.join("quarantine-held");
        require(std::fs::write(&marker, []));
        require(blocked(&mut keeper, &mut fixture, &folder));

        require(std::fs::remove_file(&marker));
        assert!(blocked(&mut keeper, &mut fixture, &folder).is_err());
        require(std::fs::write(&marker, []));
        let records = require(fixture.store.records());
        assert_eq!(records.len(), 1);
        require(fixture.store.delete_record(&records[0]));
        assert!(blocked(&mut keeper, &mut fixture, &folder).is_err());
        require(fixture.store.write_record(&records[0]));
        require(blocked(&mut keeper, &mut fixture, &folder));
        assert!(!fixture.surface.idle());

        require(std::fs::remove_file(&marker));
        require(
            fixture
                .surface
                .close_controller()
                .map_err(SurfaceError::error),
        );
        let Some(sink) = model.sink.borrow().clone() else {
            std::panic::resume_unwind(Box::new("missing modeled sink"));
        };
        let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
        retire_keeper(&mut keeper, &mut fixture);
        assert!(fixture.surface.idle());
        assert!(require(fixture.store.records()).is_empty());
        drop(sink);
        drop(fixture);
        require(root.remove());
    }

    #[test]
    fn modeled_quarantine_wipe_refusals_identify_the_failed_observation() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        let root = super::super::FixtureRoot::new()?;
        let (mut fixture, model) = super::super::model_tests::fixture(&root)?;
        let observations = [
            crate::NativeZeroObservation {
                slot: crate::BufferSlot::Request,
                before_nonzero: Some(true),
                zeroed: Some(true),
                header_present: None,
                header_unchanged: None,
            },
            crate::NativeZeroObservation {
                slot: crate::BufferSlot::Reply,
                before_nonzero: Some(true),
                zeroed: Some(true),
                header_present: Some(true),
                header_unchanged: Some(true),
            },
        ];
        let calls = model.calls.borrow().clone();
        let mut keeper = QuarantineKeeper::new();
        let keeper_held = std::rc::Rc::new(std::cell::Cell::new(false));
        let excess_observations = [observations[0]; 4];
        for (refused, wiped, observations, expected, shown) in [
            (
                false,
                true,
                observations.as_slice(),
                "refused=false wiped=true native_wiped=true",
                2,
            ),
            (
                true,
                false,
                observations.as_slice(),
                "refused=true wiped=false native_wiped=true",
                2,
            ),
            (
                true,
                true,
                &[][..],
                "refused=true wiped=true native_wiped=false",
                0,
            ),
            (
                true,
                true,
                excess_observations.as_slice(),
                "refused=true wiped=true native_wiped=false",
                3,
            ),
        ] {
            let error = observe_case(
                &mut fixture,
                &mut keeper,
                &root.0,
                &keeper_held,
                (refused, wiped, observations),
                ProcessFaultTarget::Browser,
                false,
            )
            .err()
            .map(|error| error.to_string());
            let error = error.ok_or("modeled invalid wipe evidence was accepted")?;
            assert!(error.starts_with("quarantine mappings or secrets were not wiped: case=240 "));
            assert!(error.contains(expected));
            assert!(error.contains(&format!("observation_count={}", observations.len())));
            assert!(error.contains("observations=["));
            assert_eq!(error.matches("NativeZeroObservation {").count(), shown);
            assert!(fixture.surface.idle());
            assert!(fixture.trace.borrow().is_empty());
            assert_eq!(*model.calls.borrow(), calls);
        }
        let error = observe_case(
            &mut fixture,
            &mut keeper,
            &root.0,
            &keeper_held,
            (true, true, &observations),
            ProcessFaultTarget::Browser,
            false,
        )
        .err()
        .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("quarantined owners not established"));
        assert!(fixture.trace.borrow().is_empty());
        drop(fixture);
        root.remove()
    }

    #[test]
    fn modeled_empty_keeper_refuses_retention_without_opening_a_surface() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        let root = super::super::FixtureRoot::new()?;
        let (mut fixture, model) = super::super::model_tests::fixture(&root)?;
        let calls = model.calls.borrow().clone();
        let error = blocked(&mut QuarantineKeeper::new(), &mut fixture, &root.0)
            .err()
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("quarantined owners or held folder were not retained")
        );
        assert_eq!(*model.calls.borrow(), calls);
        assert!(fixture.surface.idle());
        drop(fixture);
        root.remove()
    }

    #[test]
    fn modeled_quarantine_driver_done_refuses_without_native_work() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        let root = super::super::FixtureRoot::new()?;
        let (mut fixture, model) = super::super::model_tests::fixture(&root)?;
        let mut driver = readiness::new_driver(CeremonyId::from_bytes([240; 16]), Instant::now())?;
        let result = readiness::cancel_driver(
            &mut driver,
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        );
        assert!(fixture.finished_driver_is_done(&mut driver));
        let calls = model.calls.borrow().clone();
        let mut refused = false;
        assert_eq!(
            drive_to_quarantine(&mut fixture, &mut driver, &mut refused),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        assert!(!refused);
        assert_eq!(*model.calls.borrow(), calls);
        assert!(fixture.surface.idle());
        fixture.retire(driver, result, None)?;
        root.remove()
    }

    #[test]
    fn modeled_quarantine_finish_delegates_until_the_matching_exit() -> TestResult {
        let _port = crate::Native::fixed_port_fixture();
        let root = super::super::FixtureRoot::new()?;
        let (mut fixture, model) = super::super::model_tests::fixture(&root)?;
        let selected = super::super::fixed_competing_spec(240);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(matches!(
            fixture.surface.open(&selected),
            Poll::Ready(Ok(_))
        ));
        let mut refused = false;
        {
            let mut port = RefuseClose {
                surface: &mut fixture.surface,
                refused: &mut refused,
            };
            assert!(port.close_controller().is_err());
            assert!(port.finish().is_err());
        }
        assert!(refused);
        assert!(!fixture.surface.idle());
        fixture
            .surface
            .close_controller()
            .map_err(SurfaceError::error)?;
        let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
        let _action = sink.event(NativeEvent::BrowserExited { pid: 43 });
        {
            let mut port = RefuseClose {
                surface: &mut fixture.surface,
                refused: &mut refused,
            };
            assert!(port.finish().is_err());
            let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
            port.finish().map_err(SurfaceError::error)?;
        }
        assert!(fixture.surface.idle());
        drop(sink);
        let driver = readiness::new_driver(CeremonyId::from_bytes([240; 16]), Instant::now())?;
        fixture.retire(
            driver,
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable,
            )),
            None,
        )?;
        root.remove()
    }
}
