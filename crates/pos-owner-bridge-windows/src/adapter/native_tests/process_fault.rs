#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::io::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step};
use pos_owner_bridge::ceremony::plan::Verified;
use pos_owner_bridge::listener::FixtureProfile;
use pos_owner_bridge::{BridgeError, CleanupStore, OwnerWebSurface, SurfaceSpec, SystemClock};
use pos_owner_bridge_codec::{CeremonyId, ControlState};

use super::{readiness, retirement, FixtureRoot, TestResult};
use crate::adapter::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use crate::{
    BufferSlot, NativeFactory, NativeZeroObservation, ProcessExitState, ProcessFaultHandle,
    ProcessFaultMark, ProcessFaultState, ProcessFaultTarget,
};

type Trace = Rc<RefCell<Vec<ProcessFaultMark>>>;
type CeremonyResult = Result<Verified, BridgeError>;
type DriveResult = Result<CeremonyResult, Box<dyn std::error::Error>>;
type AttemptResult = (CeremonyResult, Option<Box<dyn std::error::Error>>);

fn expected_process_failures(
    observed: &[crate::NativeProcessFailure],
    expected: Option<ProcessFaultTarget>,
) -> bool {
    use crate::NativeProcessFailure::{BrowserExited, MainRendererExited};
    match expected {
        None => observed.is_empty(),
        Some(ProcessFaultTarget::Renderer) => observed == [MainRendererExited],
        Some(ProcessFaultTarget::Browser) => observed.is_empty() || observed == [BrowserExited],
    }
}

fn check_final_process_failures(expected: Option<ProcessFaultTarget>) -> TestResult {
    let observed = crate::Native::classified_process_failure_observations();
    if !expected_process_failures(&observed, expected) {
        return Err(
            "unexpected or unclassified native process failure during complete case".into(),
        );
    }
    Ok(())
}

#[test]
fn final_failure_evidence_rejects_late_and_unclassified_events() {
    use crate::NativeProcessFailure::{BrowserExited, MainRendererExited, Other, Unavailable};
    assert!(expected_process_failures(&[], None));
    assert!(expected_process_failures(
        &[MainRendererExited],
        Some(ProcessFaultTarget::Renderer)
    ));
    assert!(expected_process_failures(
        &[],
        Some(ProcessFaultTarget::Browser)
    ));
    assert!(expected_process_failures(
        &[BrowserExited],
        Some(ProcessFaultTarget::Browser)
    ));
    for expected in [
        None,
        Some(ProcessFaultTarget::Renderer),
        Some(ProcessFaultTarget::Browser),
    ] {
        for late in [Other, Unavailable, BrowserExited, MainRendererExited] {
            assert!(!expected_process_failures(
                &[MainRendererExited, late],
                expected
            ));
            assert!(!expected_process_failures(&[BrowserExited, late], expected));
        }
        assert!(!expected_process_failures(&[Other], expected));
        assert!(!expected_process_failures(&[Unavailable], expected));
    }
    assert!(!expected_process_failures(&[BrowserExited], None));
    assert!(!expected_process_failures(&[MainRendererExited], None));
    assert!(!expected_process_failures(
        &[],
        Some(ProcessFaultTarget::Renderer)
    ));
    assert!(!expected_process_failures(
        &[BrowserExited],
        Some(ProcessFaultTarget::Renderer)
    ));
    assert!(!expected_process_failures(
        &[MainRendererExited],
        Some(ProcessFaultTarget::Browser)
    ));
}

fn competing_spec() -> SurfaceSpec {
    let ceremony_id = CeremonyId::from_bytes([0x7f; 16]);
    SurfaceSpec {
        ceremony_id,
        folder_name: pos_owner_bridge::folder_name(&ceremony_id),
        owner_window: None,
    }
}

struct CallbackOrderGuard;

impl CallbackOrderGuard {
    fn arm() -> Self {
        crate::Native::arm_callback_order();
        Self
    }
}

impl Drop for CallbackOrderGuard {
    fn drop(&mut self) {
        crate::Native::disarm_callback_order();
    }
}

fn controller_invoked_after_exit(order: &[crate::NativeCallbackMoment], pid: u32) -> bool {
    use crate::NativeCallbackMoment::{BrowserExit, ControllerCompletion, Overflow};
    let mut exit = None;
    let mut controller = None;
    for (index, moment) in order.iter().enumerate() {
        match moment {
            BrowserExit(observed) if *observed == pid && exit.is_none() => exit = Some(index),
            ControllerCompletion(_) if controller.is_none() => controller = Some(index),
            BrowserExit(_) | ControllerCompletion(_) | Overflow => return false,
            _ => {}
        }
    }
    matches!((exit, controller), (Some(exit), Some(controller)) if exit < controller)
}

fn controller_held_before_exit(order: &[crate::NativeCallbackMoment]) -> bool {
    use crate::NativeCallbackMoment::{BrowserExit, ControllerCompletion, Overflow};
    let mut held = false;
    for moment in order {
        match moment {
            ControllerCompletion(true) if !held => held = true,
            BrowserExit(_) | ControllerCompletion(_) | Overflow => return false,
            _ => {}
        }
    }
    held
}

#[test]
fn held_controller_result_requires_its_real_callback_before_exit() {
    use crate::NativeCallbackMoment::{BrowserExit, ControllerCompletion};
    assert!(controller_held_before_exit(&[ControllerCompletion(true)]));
    assert!(!controller_held_before_exit(&[]));
    assert!(!controller_held_before_exit(&[ControllerCompletion(false)]));
    assert!(!controller_held_before_exit(&[
        ControllerCompletion(true),
        BrowserExit(42)
    ]));
}

#[test]
fn callback_order_requires_actual_unique_exit_before_controller_invocation() {
    use crate::NativeCallbackMoment::{BrowserExit, ControllerCompletion, Overflow};
    let late = [BrowserExit(42), ControllerCompletion(false)];
    assert!(controller_invoked_after_exit(&late, 42));
    assert!(!controller_invoked_after_exit(
        &[ControllerCompletion(true), BrowserExit(42)],
        42
    ));
    assert!(!controller_invoked_after_exit(
        &[BrowserExit(7), ControllerCompletion(true)],
        42
    ));
    assert!(!controller_invoked_after_exit(&[BrowserExit(42)], 42));
    assert!(!controller_invoked_after_exit(
        &[BrowserExit(42), ControllerCompletion(true), Overflow],
        42
    ));
    assert!(!controller_invoked_after_exit(
        &[BrowserExit(42), BrowserExit(42), ControllerCompletion(true)],
        42
    ));
}

struct WipeObservation {
    request_and_prf: bool,
    plan_if_quarantined: bool,
    native: bool,
}

struct FailedCaseDiagnostic {
    number: u8,
    profile: FixtureProfile,
    target: ProcessFaultTarget,
    inject: bool,
    reached: Option<ProcessFaultState>,
    error: Option<BridgeError>,
    wipe: WipeObservation,
    complete: bool,
}

impl FailedCaseDiagnostic {
    fn report(&self) {
        let _written = writeln!(std::io::stderr(),
            "NATIVE_FAULT_FINAL case={} profile={:?} target={:?} inject={} reached={:?} error={:?} wiped={} plan_wiped={} complete={} native_zeroed={}",
            self.number, self.profile, self.target, self.inject, self.reached, self.error,
            self.wipe.request_and_prf, self.wipe.plan_if_quarantined, self.complete, self.wipe.native);
    }
}

struct ZeroWitness;

impl ZeroWitness {
    fn arm() -> Self {
        crate::Native::arm_native_zero_observations();
        Self
    }
}

impl Drop for ZeroWitness {
    fn drop(&mut self) {
        let _discarded = crate::Native::take_native_zero_observations();
    }
}

fn native_zeroing_observed(observations: &[NativeZeroObservation]) -> bool {
    let [request, reply] = observations else {
        return false;
    };
    request.slot == BufferSlot::Request
        && request.before_nonzero == Some(true)
        && request.zeroed == Some(true)
        && request.header_present.is_none()
        && request.header_unchanged.is_none()
        && reply.slot == BufferSlot::Reply
        && reply.before_nonzero.is_some()
        && reply.zeroed == Some(true)
        && reply.header_present == Some(true)
        && reply.header_unchanged == Some(true)
}

#[test]
fn native_zeroing_evidence_rejects_missing_or_changed_readback() {
    let request = NativeZeroObservation {
        slot: BufferSlot::Request,
        before_nonzero: Some(true),
        zeroed: Some(true),
        header_present: None,
        header_unchanged: None,
    };
    let reply = NativeZeroObservation {
        slot: BufferSlot::Reply,
        before_nonzero: Some(false),
        zeroed: Some(true),
        header_present: Some(true),
        header_unchanged: Some(true),
    };
    assert!(native_zeroing_observed(&[request, reply]));
    assert!(!native_zeroing_observed(&[request]));
    for bad in [None, Some(false)] {
        let mut changed_request = request;
        changed_request.zeroed = bad;
        assert!(!native_zeroing_observed(&[changed_request, reply]));
        let mut changed_reply = reply;
        changed_reply.zeroed = bad;
        assert!(!native_zeroing_observed(&[request, changed_reply]));
        changed_reply = reply;
        changed_reply.header_unchanged = bad;
        assert!(!native_zeroing_observed(&[request, changed_reply]));
        changed_reply = reply;
        changed_reply.header_present = bad;
        assert!(!native_zeroing_observed(&[request, changed_reply]));
    }
    for before in [None, Some(false)] {
        let mut changed_request = request;
        changed_request.before_nonzero = before;
        assert!(!native_zeroing_observed(&[changed_request, reply]));
    }
    let mut changed_request = request;
    changed_request.header_present = Some(true);
    assert!(!native_zeroing_observed(&[changed_request, reply]));
    changed_request = request;
    changed_request.header_unchanged = Some(true);
    assert!(!native_zeroing_observed(&[changed_request, reply]));
    let mut changed_reply = reply;
    changed_reply.before_nonzero = None;
    assert!(!native_zeroing_observed(&[request, changed_reply]));
    assert!(!native_zeroing_observed(&[reply, request]));
}

impl crate::Native {
    pub(crate) fn native_verified_owned_process_faults_retire() -> TestResult {
        run()
    }
}

fn run() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    for (number, target) in [
        (0x31, ProcessFaultTarget::Renderer),
        (0x33, ProcessFaultTarget::Browser),
    ] {
        let control = run_case(Path::new(&runtime), &root.0, number, target, false)?;
        let fault = run_case(Path::new(&runtime), &root.0, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "control and fault reached different substates"
        );
    }
    run_recordless_case(Path::new(&runtime), &root.0, 0x35, false)?;
    run_recordless_case(Path::new(&runtime), &root.0, 0x36, true)?;
    for (number, target) in [
        (0x37, ProcessFaultTarget::Renderer),
        (0x39, ProcessFaultTarget::Browser),
    ] {
        let control = run_success_releasing(Path::new(&runtime), &root.0, number, target, false)?;
        let fault = run_success_releasing(Path::new(&runtime), &root.0, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "release control and fault reached different states"
        );
    }
    let control = run_success_exit(Path::new(&runtime), &root.0, 0x3b, false)?;
    let fault = run_success_exit(Path::new(&runtime), &root.0, 0x3c, true)?;
    assert_eq!(
        control, fault,
        "exit control and fault reached different states"
    );
    let control = run_awaiting_load(Path::new(&runtime), &root.0, 0x3d, false)?;
    let fault = run_awaiting_load(Path::new(&runtime), &root.0, 0x3e, true)?;
    assert_eq!(
        control, fault,
        "load control and fault reached different states"
    );
    let control = run_navigating(Path::new(&runtime), &root.0, 0x3f, false)?;
    let fault = run_navigating(Path::new(&runtime), &root.0, 0x40, true)?;
    assert_eq!(
        control, fault,
        "navigation control and fault reached different states"
    );
    for (number, target) in [
        (0x41, ProcessFaultTarget::Renderer),
        (0x43, ProcessFaultTarget::Browser),
    ] {
        let control = run_posted_empty(Path::new(&runtime), &root.0, number, target, false)?;
        let fault = run_posted_empty(Path::new(&runtime), &root.0, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "empty-reply control and fault reached different states"
        );
    }
    let control = run_pending_opening(Path::new(&runtime), &root.0, 0x45, false)?;
    let fault = run_pending_opening(Path::new(&runtime), &root.0, 0x46, true)?;
    assert_eq!(
        control, fault,
        "pending-opening control and fault reached different states"
    );
    for (number, target) in [
        (0x4b, ProcessFaultTarget::Renderer),
        (0x4d, ProcessFaultTarget::Browser),
    ] {
        let control = run_posted_writing(Path::new(&runtime), &root.0, number, target, false)?;
        let fault = run_posted_writing(Path::new(&runtime), &root.0, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "writing control and fault reached different states"
        );
    }
    for (number, target) in [
        (0x70, ProcessFaultTarget::Renderer),
        (0x72, ProcessFaultTarget::Browser),
    ] {
        let control = run_posted_ready(Path::new(&runtime), &root.0, number, target, false)?;
        let fault = run_posted_ready(Path::new(&runtime), &root.0, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "ready control and fault reached different states"
        );
    }
    run_retries(Path::new(&runtime), &root.0)?;
    run_consuming_cases(Path::new(&runtime), &root.0)?;
    run_before_record_cases(Path::new(&runtime), &root.0)?;
    root.remove()
}

struct Fixture {
    number: u8,
    profile: FixtureProfile,
    surface: Surface,
    loopback: SharedLoopback,
    store: WindowsCleanupStore,
    factory: Rc<dyn NativeFactory>,
    trace: Trace,
    handle: Option<Box<dyn ProcessFaultHandle>>,
    reached: Option<ProcessFaultState>,
    exit_reached: Option<ProcessExitState>,
    evidence_complete: bool,
    early_presence: Option<crate::RendererPresence>,
    prior_native_wipe: bool,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct FailureFinish {
    target: ProcessFaultTarget,
    inject: bool,
    actual_fault: bool,
    native_zeroed: Option<bool>,
    message: &'static str,
}

impl Fixture {
    fn finish_failed_case(
        self,
        driver: CeremonyDriver,
        result: Result<Verified, BridgeError>,
        failure: Option<Box<dyn std::error::Error>>,
        finish: FailureFinish,
    ) -> TestResult {
        let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
        let plan_wiped =
            !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
        let error = result.as_ref().err().copied();
        let complete = self.evidence_complete;
        let mark = self.trace.borrow().first().copied();
        let _written = writeln!(std::io::stderr(),
            "NATIVE_FAULT_FINAL case={} profile={:?} target={:?} inject={} reached={:?} error={:?} wiped={} plan_wiped={} complete={} native_zeroed={:?}",
            self.number, self.profile, finish.target, finish.inject, mark, error, wiped, plan_wiped, complete, finish.native_zeroed);
        self.retire(driver, result, None)?;
        let classification =
            check_final_process_failures(finish.actual_fault.then_some(finish.target));
        if let Some(error) = failure {
            return Err(error);
        }
        if error.is_none()
            || !wiped
            || !plan_wiped
            || !complete
            || finish.native_zeroed == Some(false)
        {
            return Err(format!("{}; driver error: {error:?}", finish.message).into());
        }
        classification
    }

    fn resolve_attempt(
        &mut self,
        driver: &mut CeremonyDriver,
        attempt: std::thread::Result<DriveResult>,
    ) -> AttemptResult {
        let failure = match attempt {
            Ok(Ok(result)) => return (result, None),
            Ok(Err(error)) => error,
            Err(_) => "process fault fixture panicked".into(),
        };
        let result = readiness::cancel_driver(
            driver,
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
        );
        (result, Some(failure))
    }

    fn new(
        runtime_path: &Path,
        root: &Path,
        number: u8,
        profile: FixtureProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = root.join(format!("process-fault-{number}"));
        crate::create_private_directory(&root)?;
        let runtime = Arc::new(crate::verify_fixed_runtime(runtime_path, &root)?);
        let factory: Rc<dyn NativeFactory> = Rc::new(crate::Native::owner_factory()?);
        let store = WindowsCleanupStore::open(root.clone())?;
        let loopback = SharedLoopback::start_fixture(profile)?;
        let mut surface = Surface::new(
            Rc::clone(&factory),
            runtime,
            root,
            Box::new(loopback.clone()),
            Box::new(store.clone()),
            Box::new(SystemClock),
        )
        .map_err(pos_owner_bridge::SurfaceError::error)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        surface.set_deadline(deadline);
        Ok(Self {
            number,
            profile,
            surface,
            loopback,
            store,
            factory,
            trace: Rc::new(RefCell::new(Vec::new())),
            handle: None,
            reached: None,
            exit_reached: None,
            evidence_complete: false,
            early_presence: None,
            prior_native_wipe: false,
            deadline,
        })
    }

    fn drive(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.reached.is_none()
                && matches!(&step, Step::Pending)
                && driver.first_receipt_at().is_some()
            {
                self.at_fault_point(driver, target, inject)?;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn at_fault_point(
        &mut self,
        driver: &CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> TestResult {
        let state = self
            .surface
            .posted_fault_state(driver.posts())
            .map_err(|()| "unverified pre-fault state")?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::Received) {
            return Err("the page was not in RECEIVED".into());
        }
        self.reached = Some(state);
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::Reached(state));
        if inject {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline: self.deadline,
            };
            self.handle = Some(
                self.surface
                    .inject_posted_fault(target, seal)
                    .map_err(|()| "owned process fault refused")?,
            );
            self.observe_fault(target)?;
        } else {
            if self.trace.borrow().as_slice() != [ProcessFaultMark::Reached(state)] {
                return Err("control trace changed".into());
            }
            self.evidence_complete = true;
        }
        if !self.evidence_complete || !self.surface.fault_owners_retained() {
            return Err("fault evidence or native owners missing before cleanup".into());
        }
        self.check_blocked_admission()?;
        if !inject {
            self.surface.controller_lost();
        }
        writeln!(
            std::io::stderr(),
            "NATIVE_PROCESS_FAULT target={target:?} injected={inject} trace={:?}",
            self.trace.borrow()
        )?;
        Ok(())
    }

    fn check_blocked_admission(&mut self) -> TestResult {
        if !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            || !self.surface.fault_owners_retained()
        {
            return Err("a competing Surface opening was not blocked".into());
        }
        Ok(())
    }

    fn observe_fault(&mut self, target: ProcessFaultTarget) -> TestResult {
        let state = self.reached.ok_or("pre-fault state disappeared")?;
        self.observe_fault_from(target, ProcessFaultMark::Reached(state))
    }

    fn observe_fault_from(
        &mut self,
        target: ProcessFaultTarget,
        first: ProcessFaultMark,
    ) -> TestResult {
        // Progress the owning STA until its actual event; never wait on a process
        // handle or infer an exit from a PID. Query the retained handle once when
        // that event arrives; an indeterminate result fails this case.
        loop {
            if let Some(event) = self
                .surface
                .posted_fault_event(target)
                .map_err(|()| "unexpected native fault event")?
            {
                let held = self.handle.as_ref().ok_or("fault handle disappeared")?;
                let identity = held.identity();
                let code = held
                    .exit_code()
                    .map_err(|()| "exit query failed")?
                    .ok_or("exit still pending at native event")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                let expected_event = match target {
                    ProcessFaultTarget::Renderer => ProcessFaultMark::MainRendererExited,
                    ProcessFaultTarget::Browser => ProcessFaultMark::OwnBrowserExited,
                };
                if self.trace.borrow().as_slice()
                    != [
                        first,
                        ProcessFaultMark::Selected(identity),
                        ProcessFaultMark::TerminationCall,
                        expected_event,
                        ProcessFaultMark::ExitCode(0x535),
                    ]
                {
                    return Err("ordered native fault evidence is incomplete".into());
                }
                self.evidence_complete = true;
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("native fault event timed out".into());
            }
            readiness::pump(&self.surface)?;
        }
    }

    fn retire(
        mut self,
        driver: CeremonyDriver,
        result: Result<Verified, BridgeError>,
        restart_orphans: Option<CeremonyId>,
    ) -> TestResult {
        retirement::retire(
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
            driver,
            result,
            |_, _, _| {},
        );
        // Retain the process object and its creating STA through actual retirement.
        drop(self.handle.take());
        drop(self.surface);
        assert!(self.store.records()?.is_empty());
        Rc::get_mut(&mut self.factory)
            .ok_or("fault factory still shared")?
            .stop()?;
        if let Some(ceremony_id) = restart_orphans {
            let expected = pos_owner_bridge::folder_name(&ceremony_id);
            if self
                .store
                .folders()?
                .iter()
                .any(|folder| folder != &expected)
            {
                return Err("unexpected folder in recordless restart root".into());
            }
            restart_recordless_orphans(&mut self.store)?;
        }
        if !self.store.folders()?.is_empty() {
            return Err("recordless folder retained for restart".into());
        }
        Ok(())
    }
}

fn run_case(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let _zero_witness = ZeroWitness::arm();
    let started = Instant::now();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), started)?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let slot_wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped_if_quarantined =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let error = result.as_ref().err().copied();
    let reached = fixture.reached;
    let complete_before_cleanup = fixture.evidence_complete;
    let failures = crate::Native::process_failure_observations();
    let native_zeroed = native_zeroing_observed(&crate::Native::take_native_zero_observations());
    FailedCaseDiagnostic {
        number,
        profile: FixtureProfile::Pending,
        target,
        inject,
        reached,
        error,
        wipe: WipeObservation {
            request_and_prf: slot_wiped,
            plan_if_quarantined: plan_wiped_if_quarantined,
            native: native_zeroed,
        },
        complete: complete_before_cleanup,
    }
    .report();
    fixture.retire(driver, result, None)?;
    let classification = check_final_process_failures(inject.then_some(target));
    if let Some(error) = failure {
        return Err(error);
    }
    if !complete_before_cleanup {
        return Err(format!(
            "fault evidence was not established before cleanup; driver error: {error:?}"
        )
        .into());
    }
    classification?;
    if !slot_wiped || !plan_wiped_if_quarantined {
        return Err("failed ceremony secrets were not wiped at their required boundary".into());
    }
    if !native_zeroed {
        return Err("live native mappings did not prove zeroization and retained header".into());
    }
    if inject && target == ProcessFaultTarget::Renderer {
        assert_eq!(failures, [Some(true)]);
        assert_eq!(
            error,
            Some(BridgeError::Lifecycle(
                pos_owner_bridge::LifecycleCode::RendererFailed
            ))
        );
    } else if !inject {
        assert!(failures.is_empty());
        assert!(error.is_some());
    } else {
        assert!(error.is_some());
    }
    reached.ok_or_else(|| "fault point was not reached".into())
}

impl Fixture {
    fn check_recordless_admission(&mut self) -> TestResult {
        if !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            || !self.surface.recordless_fault_owners_retained()
        {
            return Err("a competing recordless Surface opening was not blocked".into());
        }
        Ok(())
    }

    fn drive_recordless(
        &mut self,
        driver: &mut CeremonyDriver,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        let mut reached_opening = false;
        let mut cancelled = false;
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if !reached_opening
                && matches!(&step, Step::Pending)
                && self.surface.recordless_opening_ready()
            {
                if driver.generation() != 1 {
                    return Err("unexpected recordless generation".into());
                }
                self.await_recordless_controller()?;
                let browser = self
                    .surface
                    .prepare_recordless_browser()
                    .map_err(|()| "recordless browser ownership is indeterminate")?;
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::RecordlessOpening {
                        generation: 1,
                        record_count: 0,
                    });
                if !self.surface.recordless_fault_owners_retained() {
                    return Err("recordless control did not retain the opening owners".into());
                }
                self.check_recordless_admission()?;
                writeln!(
                    std::io::stderr(),
                    "NATIVE_RECORDLESS_OPENING injected={inject} trace={:?}",
                    self.trace.borrow()
                )?;
                reached_opening = true;
                if inject {
                    self.handle = Some(
                        self.surface
                            .inject_recordless_browser(crate::FaultSeal {
                                trace: Rc::clone(&self.trace),
                                deadline: self.deadline,
                            })
                            .map_err(|()| "recordless browser fault refused")?,
                    );
                    self.observe_recordless(browser)?;
                    if !self.surface.recordless_fault_owners_retained() {
                        return Err("recordless owners not retained before cleanup".into());
                    }
                    self.check_recordless_admission()?;
                    writeln!(
                        std::io::stderr(),
                        "NATIVE_RECORDLESS_BROWSER trace={:?}",
                        self.trace.borrow()
                    )?;
                    self.surface.controller_lost();
                    cancelled = true;
                }
            }
            if !inject && reached_opening && !cancelled && driver.first_receipt_at().is_some() {
                if self.trace.borrow().as_slice()
                    != [ProcessFaultMark::RecordlessOpening {
                        generation: 1,
                        record_count: 0,
                    }]
                {
                    return Err("recordless control trace changed".into());
                }
                self.evidence_complete = true;
                self.surface.controller_lost();
                cancelled = true;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("recordless driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn await_recordless_controller(&self) -> TestResult {
        // Let the actual completion arrive without consuming it or advancing
        // the driver; the held callback still owns its result and STA.
        loop {
            match self.surface.recordless_controller_completion() {
                Some(true) if controller_held_before_exit(&crate::Native::callback_order()) => {
                    return Ok(())
                }
                Some(true) => return Err("recordless callback order was not established".into()),
                Some(false) => return Err("recordless controller creation failed".into()),
                None if Instant::now() >= self.deadline => {
                    return Err("recordless controller completion timed out".into())
                }
                None => readiness::pump(&self.surface)?,
            }
        }
    }

    fn retain_recordless_until_exit(&self) {
        if self.handle.is_none() {
            return;
        }
        // A failed assertion or timeout is never permission to release the
        // subscribed environment or its pending controller callback.
        while !matches!(self.surface.recordless_fault_event(), Ok(Some(_))) {
            readiness::pump_retaining(&self.surface);
        }
    }

    fn observe_recordless(&mut self, browser: pos_owner_bridge::ProcessIdentity) -> TestResult {
        loop {
            if let Some(event) = self
                .surface
                .recordless_fault_event()
                .map_err(|()| "mismatched recordless browser exit")?
            {
                let held = self
                    .handle
                    .as_ref()
                    .ok_or("recordless handle disappeared")?;
                let code = held
                    .exit_code()
                    .map_err(|()| "recordless exit query failed")?
                    .ok_or("recordless process exit pending")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                if held.identity() != browser
                    || self.trace.borrow().as_slice()
                        != [
                            ProcessFaultMark::RecordlessOpening {
                                generation: 1,
                                record_count: 0,
                            },
                            ProcessFaultMark::Selected(browser),
                            ProcessFaultMark::TerminationCall,
                            ProcessFaultMark::OwnBrowserExited,
                            ProcessFaultMark::ExitCode(0x535),
                        ]
                {
                    return Err("recordless fault evidence is incomplete".into());
                }
                self.evidence_complete = true;
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("recordless browser exit timed out".into());
            }
            readiness::pump(&self.surface)?;
        }
    }
}

fn run_recordless_case(runtime: &Path, root: &Path, number: u8, inject: bool) -> TestResult {
    let _callback_order = CallbackOrderGuard::arm();
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_recordless(&mut driver, inject)
    }));
    if !matches!(&attempt, Ok(Ok(_))) {
        fixture.retain_recordless_until_exit();
    }
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let slot_wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped_if_quarantined =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let evidence_complete = fixture.evidence_complete;
    let failures = crate::Native::process_failure_observations();
    let result_error = result.as_ref().err().copied();
    // Only an already observed matching browser exit permits the real startup
    // orphan sweep. A failed case preserves its folder and returns an error.
    let restart = (inject && evidence_complete).then_some(CeremonyId::from_bytes([number; 16]));
    fixture.retire(driver, result, restart)?;
    check_final_process_failures(inject.then_some(ProcessFaultTarget::Browser))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !evidence_complete || result_error.is_none() {
        return Err("recordless evidence incomplete".into());
    }
    if !slot_wiped || !plan_wiped_if_quarantined {
        return Err("recordless ceremony secrets were not wiped at their required boundary".into());
    }
    if !inject && !failures.is_empty() {
        return Err("recordless no-fault control observed a process failure".into());
    }
    Ok(())
}

fn has_synthetic_success_prf(driver: &CeremonyDriver) -> bool {
    driver.prf().iter().copied().eq(0xa0_u8..=0xbf)
}

impl Fixture {
    fn drive_success_releasing(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            // The release transition occurs inside this step. Its start is a
            // conservative lower bound for the driver's real release deadline.
            let step_started = Instant::now();
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.reached.is_none()
                && matches!(&step, Step::Pending)
                && has_synthetic_success_prf(driver)
            {
                let deadline = self
                    .deadline
                    .min(step_started + pos_owner_bridge::ceremony::timing::RELEASE_WINDOW);
                self.at_success_releasing(driver, target, inject, deadline)?;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("success driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn at_success_releasing(
        &mut self,
        driver: &CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
        deadline: Instant,
    ) -> TestResult {
        let state = self
            .surface
            .releasing_fault_state(driver.posts())
            .map_err(|()| "successful release state was not established")?;
        if Instant::now() >= deadline {
            return Err("successful release fault point expired".into());
        }
        self.reached = Some(state);
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::Reached(state));
        if inject {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline,
            };
            self.handle = Some(
                self.surface
                    .inject_releasing_fault(target, seal)
                    .map_err(|()| "successful release fault refused")?,
            );
            self.observe_fault(target)?;
        } else {
            self.evidence_complete = true;
        }
        if !self.evidence_complete || !self.surface.fault_owners_retained() {
            return Err("successful release owners or evidence missing".into());
        }
        self.check_blocked_admission()?;
        writeln!(
            std::io::stderr(),
            "NATIVE_SUCCESS_RELEASING target={target:?} injected={inject} trace={:?}",
            self.trace.borrow()
        )?;
        Ok(())
    }
}

fn run_success_releasing(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_success_releasing(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let verified = result.is_ok() && has_synthetic_success_prf(&driver) && driver.request_clear();
    let reached = fixture.reached;
    let complete = fixture.evidence_complete;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
    check_final_process_failures(inject.then_some(target))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !verified || !complete || !native_zeroed {
        return Err("successful release or nonzero native reply wipe was not established".into());
    }
    reached.ok_or_else(|| "successful release point was not reached".into())
}

impl Fixture {
    fn drive_success_exit(
        &mut self,
        driver: &mut CeremonyDriver,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            // The transition to AwaitingExit occurs inside this driver step;
            // its start is a conservative lower bound for the real deadline.
            let step_started = Instant::now();
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.exit_reached.is_none()
                && matches!(&step, Step::Pending)
                && has_synthetic_success_prf(driver)
                && self.surface.exit_fault_phase_reached()
            {
                let deadline = self
                    .deadline
                    .min(step_started + pos_owner_bridge::ceremony::timing::EXIT_WINDOW);
                self.at_success_exit(inject, deadline)?;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("success exit driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn at_success_exit(&mut self, inject: bool, deadline: Instant) -> TestResult {
        let state = self
            .surface
            .exit_fault_state()
            .map_err(|()| "owned live browser in AwaitingExit was not established")?;
        if Instant::now() >= deadline {
            return Err("successful exit fault point expired".into());
        }
        self.exit_reached = Some(state);
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::ReachedExit(state));
        if inject {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline,
            };
            self.handle = Some(
                self.surface
                    .inject_exit_fault(seal)
                    .map_err(|()| "successful exit fault refused")?,
            );
            self.observe_fault_from(
                ProcessFaultTarget::Browser,
                ProcessFaultMark::ReachedExit(state),
            )?;
        } else {
            self.evidence_complete = true;
        }
        if !self.evidence_complete || !self.surface.exit_fault_owners_retained() {
            return Err("successful exit owners or evidence missing".into());
        }
        if !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            || !self.surface.exit_fault_owners_retained()
        {
            return Err("a competing exit-phase Surface opening was not blocked".into());
        }
        writeln!(
            std::io::stderr(),
            "NATIVE_SUCCESS_EXIT injected={inject} trace={:?}",
            self.trace.borrow()
        )?;
        Ok(())
    }
}

fn run_success_exit(
    runtime: &Path,
    root: &Path,
    number: u8,
    inject: bool,
) -> Result<ProcessExitState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_success_exit(&mut driver, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let verified = result.is_ok() && has_synthetic_success_prf(&driver) && driver.request_clear();
    let reached = fixture.exit_reached;
    let complete = fixture.evidence_complete;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
    check_final_process_failures(inject.then_some(ProcessFaultTarget::Browser))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !verified || !complete || !native_zeroed {
        return Err("successful exit or nonzero native reply wipe was not established".into());
    }
    reached.ok_or_else(|| "successful exit point was not reached".into())
}

fn restart_recordless_orphans(store: &mut WindowsCleanupStore) -> TestResult {
    use pos_owner_bridge::fake::clock::{FakeClock, FakeRandom};
    use pos_owner_bridge::fake::honest::{HonestConfig, HonestPage};
    use pos_owner_bridge::fake::host::{FakeLoopback, FakeStore};
    use pos_owner_bridge::fake::stepper::FakeHost;
    use pos_owner_bridge::fake::surface::{FakeSurface, SurfaceConfig};
    use pos_owner_bridge::{BridgeConfig, OwnerBridge, RestartProgress};

    let clock = FakeClock::start();
    let loopback = FakeLoopback::default();
    let page = HonestPage::new(HonestConfig::standard(&[1])).map_err(|error| error.to_string())?;
    let surface = FakeSurface::new(
        clock.clone(),
        loopback.clone(),
        Box::new(page),
        SurfaceConfig::default(),
    );
    let host = FakeHost::new(clock.clone(), surface, loopback, FakeStore::default());
    let mut bridge = OwnerBridge::new(host, FakeRandom::seeded(1), clock, BridgeConfig::default());
    let mut probe = crate::WindowsProcessProbe;
    let progress = bridge.start_restart_check(store, &mut probe)?;
    if progress != (RestartProgress::Done { deferred: 0 }) {
        return Err("recordless restart cleanup remains deferred".into());
    }
    Ok(())
}

impl Fixture {
    fn drive_awaiting_load(
        &mut self,
        driver: &mut CeremonyDriver,
        inject: bool,
    ) -> Result<(Result<Verified, BridgeError>, ProcessFaultMark), Box<dyn std::error::Error>> {
        let mut reached = None;
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if reached.is_none()
                && matches!(&step, Step::Pending)
                && self.surface.awaiting_load_fault_ready()
            {
                let mark = self
                    .surface
                    .awaiting_load_fault_state(driver.generation(), driver.posts())
                    .map_err(|()| "awaiting-load fault state could not be established")?;
                self.trace.borrow_mut().push(mark);
                if inject {
                    let seal = crate::FaultSeal {
                        trace: Rc::clone(&self.trace),
                        deadline: self.deadline,
                    };
                    self.handle = Some(
                        self.surface
                            .inject_awaiting_load_fault(ProcessFaultTarget::Browser, seal)
                            .map_err(|()| "awaiting-load process fault refused")?,
                    );
                    self.observe_fault_from(ProcessFaultTarget::Browser, mark)?;
                } else {
                    self.evidence_complete = true;
                }
                if !self.evidence_complete
                    || !self.surface.awaiting_load_fault_owners_retained()
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || !self.surface.awaiting_load_fault_owners_retained()
                {
                    return Err("awaiting-load owners or blocked admission missing".into());
                }
                if !inject {
                    self.surface.controller_lost();
                }
                reached = Some(mark);
                writeln!(
                    std::io::stderr(),
                    "NATIVE_AWAITING_LOAD injected={inject} trace={:?}",
                    self.trace.borrow()
                )?;
            }
            match step {
                Step::Finished(result) => {
                    return Ok((
                        result,
                        reached.ok_or("awaiting-load state was not observed")?,
                    ))
                }
                Step::Done => return Err("awaiting-load driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_awaiting_load(
    runtime: &Path,
    root: &Path,
    number: u8,
    inject: bool,
) -> Result<ProcessFaultMark, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_awaiting_load(&mut driver, inject)
    }));
    let mut mark = None;
    let attempt = attempt.map(|result| {
        result.map(|(outcome, reached)| {
            mark = Some(reached);
            outcome
        })
    });
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let finish = FailureFinish {
        target: ProcessFaultTarget::Browser,
        inject,
        actual_fault: inject,
        native_zeroed: None,
        message: "awaiting-load failure, wipe, or evidence was not established",
    };
    fixture.finish_failed_case(driver, result, failure, finish)?;
    mark.ok_or_else(|| "awaiting-load state was not reached".into())
}

impl Fixture {
    fn drive_navigating(
        &mut self,
        driver: &mut CeremonyDriver,
        inject: bool,
    ) -> Result<(Result<Verified, BridgeError>, ProcessFaultMark), Box<dyn std::error::Error>> {
        let mut reached = None;
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if reached.is_none()
                && matches!(&step, Step::Pending)
                && self.surface.navigating_fault_ready()
            {
                let mark = self
                    .surface
                    .navigating_fault_state(driver.generation(), driver.posts())
                    .map_err(|()| "navigating fault state could not be established")?;
                self.trace.borrow_mut().push(mark);
                if inject {
                    let seal = crate::FaultSeal {
                        trace: Rc::clone(&self.trace),
                        deadline: self.deadline,
                    };
                    self.handle = Some(
                        self.surface
                            .inject_navigating_fault(ProcessFaultTarget::Browser, seal)
                            .map_err(|()| "navigating process fault refused")?,
                    );
                    self.observe_fault_from(ProcessFaultTarget::Browser, mark)?;
                } else {
                    self.evidence_complete = true;
                }
                if !self.evidence_complete
                    || !self.surface.navigating_fault_owners_retained()
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || !self.surface.navigating_fault_owners_retained()
                {
                    return Err("navigating owners or blocked admission missing".into());
                }
                if !inject {
                    self.surface.controller_lost();
                }
                reached = Some(mark);
                writeln!(
                    std::io::stderr(),
                    "NATIVE_NAVIGATING injected={inject} trace={:?}",
                    self.trace.borrow()
                )?;
            }
            match step {
                Step::Finished(result) => {
                    return Ok((result, reached.ok_or("navigating state was not observed")?))
                }
                Step::Done => return Err("navigating driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_navigating(
    runtime: &Path,
    root: &Path,
    number: u8,
    inject: bool,
) -> Result<ProcessFaultMark, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_navigating(&mut driver, inject)
    }));
    let mut mark = None;
    let attempt = attempt.map(|result| {
        result.map(|(outcome, reached)| {
            mark = Some(reached);
            outcome
        })
    });
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let finish = FailureFinish {
        target: ProcessFaultTarget::Browser,
        inject,
        actual_fault: inject,
        native_zeroed: None,
        message: "navigating failure, wipe, or evidence was not established",
    };
    fixture.finish_failed_case(driver, result, failure, finish)?;
    mark.ok_or_else(|| "navigating state was not reached".into())
}

impl Fixture {
    fn drive_posted_empty(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.reached.is_none()
                && matches!(&step, Step::Pending)
                && driver.posts() == 1
                && driver.first_receipt_at().is_none()
            {
                let deadline = self.deadline.min(
                    driver
                        .next_wake()
                        .ok_or("empty-reply driver deadline missing")?,
                );
                let state = self
                    .surface
                    .posted_empty_fault_state(driver.posts())
                    .map_err(|()| "empty-reply fault state was not observed")?;
                if Instant::now() >= deadline {
                    return Err("empty-reply fault point expired".into());
                }
                self.reached = Some(state);
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::Reached(state));
                if inject {
                    let seal = crate::FaultSeal {
                        trace: Rc::clone(&self.trace),
                        deadline,
                    };
                    self.handle = Some(
                        self.surface
                            .inject_posted_empty_fault(target, seal)
                            .map_err(|()| "empty-reply owned fault refused")?,
                    );
                    self.observe_fault(target)?;
                } else {
                    self.evidence_complete = true;
                }
                if !self.evidence_complete || !self.surface.fault_owners_retained() {
                    return Err("empty-reply evidence or owners missing".into());
                }
                self.check_blocked_admission()?;
                if !inject {
                    self.surface.controller_lost();
                }
                writeln!(
                    std::io::stderr(),
                    "NATIVE_POSTED_EMPTY target={target:?} injected={inject} trace={:?}",
                    self.trace.borrow()
                )?;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("empty-reply driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_posted_empty(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::DelayedDelivery)?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_posted_empty(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let state = fixture.reached;
    let native_zeroed = native_zeroing_observed(&crate::Native::take_native_zero_observations());
    let finish = FailureFinish {
        target,
        inject,
        actual_fault: inject,
        native_zeroed: Some(native_zeroed),
        message: "empty-reply failure, wipe, or evidence was not established",
    };
    fixture.finish_failed_case(driver, result, failure, finish)?;
    state.ok_or_else(|| "empty-reply state was not reached".into())
}

impl Fixture {
    fn drive_pending_opening(
        &mut self,
        driver: &mut CeremonyDriver,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        let mut reached = false;
        let mut cancelled = false;
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if !reached && matches!(&step, Step::Pending) && self.surface.recordless_opening_ready()
            {
                if driver.generation() != 1
                    || driver.posts() != 0
                    || self.surface.pending_opening_completion().is_some()
                {
                    return Err("controller creation was not pending".into());
                }
                let browser = self
                    .surface
                    .prepare_pending_opening_browser()
                    .map_err(|()| "pending-opening browser or callback indeterminate")?;
                let first = ProcessFaultMark::PendingOpening {
                    generation: 1,
                    record_count: 0,
                };
                self.trace.borrow_mut().push(first);
                if !self.surface.pending_opening_owners_retained()
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || !self.surface.pending_opening_owners_retained()
                {
                    return Err("pending-opening owners or blocked admission missing".into());
                }
                reached = true;
                if inject {
                    let seal = crate::FaultSeal {
                        trace: Rc::clone(&self.trace),
                        deadline: self.deadline,
                    };
                    self.handle = Some(
                        self.surface
                            .inject_pending_opening_browser(seal)
                            .map_err(|()| "pending-opening browser fault refused")?,
                    );
                    self.observe_pending_opening(browser, first)?;
                    if !self.surface.pending_opening_owners_retained() {
                        return Err("pending-opening callback owner not retained".into());
                    }
                    self.surface.controller_lost();
                    cancelled = true;
                }
            }
            if !inject && reached && !cancelled && driver.first_receipt_at().is_some() {
                self.evidence_complete = true;
                self.surface.controller_lost();
                cancelled = true;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("pending-opening driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn observe_pending_opening(
        &mut self,
        browser: pos_owner_bridge::ProcessIdentity,
        first: ProcessFaultMark,
    ) -> TestResult {
        loop {
            if let Some(event) = self
                .surface
                .recordless_fault_event()
                .map_err(|()| "pending-opening browser exit mismatched")?
            {
                let held = self
                    .handle
                    .as_ref()
                    .ok_or("pending-opening handle disappeared")?;
                let code = held
                    .exit_code()
                    .map_err(|()| "pending-opening exit query failed")?
                    .ok_or("pending-opening process exit pending")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                if held.identity() != browser
                    || self.trace.borrow().as_slice()
                        != [
                            first,
                            ProcessFaultMark::Selected(browser),
                            ProcessFaultMark::TerminationCall,
                            ProcessFaultMark::OwnBrowserExited,
                            ProcessFaultMark::ExitCode(0x535),
                        ]
                {
                    return Err("pending-opening fault evidence is incomplete".into());
                }
                break;
            }
            if Instant::now() >= self.deadline {
                return Err("pending-opening browser exit timed out".into());
            }
            readiness::pump(&self.surface)?;
        }
        loop {
            if let Some(success) = self.surface.pending_opening_completion() {
                if !controller_invoked_after_exit(
                    &crate::Native::callback_order(),
                    browser.browser_pid,
                ) {
                    return Err(
                        "controller completion was not invoked after the matching exit".into(),
                    );
                }
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::ControllerCompletion(success));
                self.evidence_complete = true;
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("late controller completion was not observed".into());
            }
            readiness::pump(&self.surface)?;
        }
    }
}

fn run_pending_opening(
    runtime: &Path,
    root: &Path,
    number: u8,
    inject: bool,
) -> Result<ProcessFaultMark, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let _callback_order = CallbackOrderGuard::arm();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let ceremony_id = CeremonyId::from_bytes([number; 16]);
    let mut driver = readiness::new_driver(ceremony_id, Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_pending_opening(&mut driver, inject)
    }));
    if !matches!(&attempt, Ok(Ok(_))) {
        fixture.retain_recordless_until_exit();
    }
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let failed = result.is_err();
    let complete = fixture.evidence_complete;
    let first = fixture.trace.borrow().first().copied();
    let restart = (inject && complete).then_some(ceremony_id);
    fixture.retire(driver, result, restart)?;
    check_final_process_failures(inject.then_some(ProcessFaultTarget::Browser))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !failed || !wiped || !plan_wiped || !complete {
        return Err("pending-opening failure, wipe, or evidence was not established".into());
    }
    first.ok_or_else(|| "pending-opening state was not reached".into())
}

impl Fixture {
    fn drive_posted_writing(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> DriveResult {
        let mut writing_seen = None;
        loop {
            let step_started = Instant::now();
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.reached.is_none()
                && matches!(&step, Step::Pending)
                && driver.first_receipt_at().is_some()
            {
                let state = self
                    .surface
                    .reply_load_state()
                    .map_err(|_| "writing reply read failed")?;
                if state == ControlState::Writing as u32 {
                    let first = *writing_seen.get_or_insert_with(Instant::now);
                    // Let the real driver poll again after the observed WRITING,
                    // so the state has been accepted before the fixed fault.
                    if step_started.saturating_duration_since(first)
                        >= pos_owner_bridge::ceremony::timing::FAST_POLL
                    {
                        self.at_posted_writing(driver, target, inject)?;
                    }
                } else if writing_seen.is_some() {
                    return Err("writing phase advanced before its fault point".into());
                }
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("writing driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn at_posted_writing(
        &mut self,
        driver: &CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> TestResult {
        let deadline = self.deadline.min(
            driver
                .next_wake()
                .ok_or("writing driver deadline missing")?,
        );
        let state = self
            .surface
            .posted_writing_fault_state(driver.posts())
            .map_err(|()| "writing fault state was not established")?;
        if Instant::now() >= deadline {
            return Err("writing fault point expired".into());
        }
        self.reached = Some(state);
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::Reached(state));
        if inject {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline,
            };
            self.handle = Some(
                self.surface
                    .inject_posted_writing_fault(target, seal)
                    .map_err(|()| "owned writing fault refused")?,
            );
            self.observe_fault(target)?;
        } else {
            self.evidence_complete = true;
        }
        if !self.evidence_complete || !self.surface.fault_owners_retained() {
            return Err("writing evidence or owners missing".into());
        }
        self.check_blocked_admission()?;
        if !inject {
            self.surface.controller_lost();
        }
        writeln!(
            std::io::stderr(),
            "NATIVE_POSTED_WRITING target={target:?} injected={inject} trace={:?}",
            self.trace.borrow()
        )?;
        Ok(())
    }
}

fn run_posted_writing(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetWritingDelay,
    )?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_posted_writing(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let state = fixture.reached;
    let native_zeroed = native_zeroing_observed(&crate::Native::take_native_zero_observations());
    fixture.finish_failed_case(
        driver,
        result,
        failure,
        FailureFinish {
            target,
            inject,
            actual_fault: inject,
            native_zeroed: Some(native_zeroed),
            message: "writing failure, wipe, or evidence was not established",
        },
    )?;
    state.ok_or_else(|| "writing state was not reached".into())
}

impl Fixture {
    fn drive_posted_ready(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> DriveResult {
        loop {
            // Inspect after pumping and before the next driver step: that step
            // may otherwise consume READY immediately in the same call.
            if self.reached.is_none() && driver.first_receipt_at().is_some() {
                let state = self
                    .surface
                    .reply_load_state()
                    .map_err(|_| "ready reply read failed")?;
                if state == ControlState::Ready as u32 {
                    self.at_posted_ready(driver, target, inject)?;
                }
            }
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("ready driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn at_posted_ready(
        &mut self,
        driver: &CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> TestResult {
        let deadline = self
            .deadline
            .min(driver.next_wake().ok_or("ready driver deadline missing")?);
        let state = self
            .surface
            .posted_ready_fault_state(driver.posts())
            .map_err(|()| "ready fault state was not established")?;
        if Instant::now() >= deadline {
            return Err("ready fault point expired".into());
        }
        self.reached = Some(state);
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::Reached(state));
        if inject {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline,
            };
            self.handle = Some(
                self.surface
                    .inject_posted_ready_fault(target, seal)
                    .map_err(|()| "owned ready fault refused")?,
            );
            self.observe_fault(target)?;
        } else {
            self.evidence_complete = true;
        }
        if !self.evidence_complete || !self.surface.fault_owners_retained() {
            return Err("ready evidence or owners missing".into());
        }
        self.check_blocked_admission()?;
        if !inject {
            self.surface.controller_lost();
        }
        writeln!(
            std::io::stderr(),
            "NATIVE_POSTED_READY target={target:?} injected={inject} trace={:?}",
            self.trace.borrow()
        )?;
        Ok(())
    }
}

fn run_posted_ready(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_posted_ready(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let state = fixture.reached;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.finish_failed_case(
        driver,
        result,
        failure,
        FailureFinish {
            target,
            inject,
            actual_fault: inject,
            native_zeroed: Some(native_zeroed),
            message: "ready failure, wipe, or evidence was not established",
        },
    )?;
    state.ok_or_else(|| "ready state was not reached".into())
}

fn run_retries(runtime: &Path, root: &Path) -> TestResult {
    use crate::RetryPoint::{Eighth, Fifth, Fourth, Second, Seventh, Sixth, Third};
    for point in [Second, Third, Fourth, Fifth, Sixth, Seventh, Eighth] {
        for (index, target) in [
            (0_u8, ProcessFaultTarget::Renderer),
            (2, ProcessFaultTarget::Browser),
        ] {
            let number = 0x50 + (point.post() - 2) * 4 + index;
            let control = run_posted_retry(runtime, root, number, target, point, false)?;
            let fault = run_posted_retry(runtime, root, number + 1, target, point, true)?;
            assert_eq!(
                control, fault,
                "retry control and fault reached different states"
            );
        }
    }
    Ok(())
}
impl Fixture {
    fn drive_posted_retry(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        point: crate::RetryPoint,
        inject: bool,
    ) -> Result<Result<Verified, BridgeError>, Box<dyn std::error::Error>> {
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if self.reached.is_none()
                && matches!(&step, Step::Pending)
                && driver.posts() == point.post()
                && driver.first_receipt_at().is_none()
            {
                let deadline = self.deadline.min(
                    driver
                        .next_wake()
                        .ok_or("retry empty-reply driver deadline missing")?,
                );
                let previous = crate::Native::take_native_zero_observations();
                if previous.len() != usize::from(point.post() - 1) * 2
                    || !previous.chunks_exact(2).all(native_zeroing_observed)
                {
                    return Err("retired retry pairs did not prove their native wipes".into());
                }
                self.prior_native_wipe = true;
                // Taking the completed-pair observations disarms the witness;
                // re-arm it for the currently live pair before any fault.
                crate::Native::arm_native_zero_observations();
                let state = self
                    .surface
                    .posted_retry_fault_state(driver.posts(), point)
                    .map_err(|()| "retry empty-reply fault state was not observed")?;
                if Instant::now() >= deadline {
                    return Err("retry empty-reply fault point expired".into());
                }
                self.reached = Some(state);
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::Reached(state));
                if inject {
                    let seal = crate::FaultSeal {
                        trace: Rc::clone(&self.trace),
                        deadline,
                    };
                    self.handle = Some(
                        self.surface
                            .inject_posted_retry_fault(target, point, seal)
                            .map_err(|()| "retry empty-reply owned fault refused")?,
                    );
                    self.observe_fault(target)?;
                } else {
                    self.evidence_complete = true;
                }
                if !self.evidence_complete || !self.surface.fault_owners_retained() {
                    return Err("retry empty-reply evidence or owners missing".into());
                }
                self.check_blocked_admission()?;
                if !inject {
                    self.surface.controller_lost();
                }
                writeln!(
                    std::io::stderr(),
                    "NATIVE_POSTED_RETRY_EMPTY target={target:?} injected={inject} trace={:?}",
                    self.trace.borrow()
                )?;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("retry empty-reply driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_posted_retry(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    point: crate::RetryPoint,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::WithheldDelivery)?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_posted_retry(&mut driver, target, point, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let state = fixture.reached;
    let native_zeroed = fixture.prior_native_wipe
        && native_zeroing_observed(&crate::Native::take_native_zero_observations());
    fixture.finish_failed_case(
        driver,
        result,
        failure,
        FailureFinish {
            target,
            inject,
            actual_fault: inject,
            native_zeroed: Some(native_zeroed),
            message: "retry empty-reply failure, wipe, or evidence was not established",
        },
    )?;
    state.ok_or_else(|| "retry empty-reply state was not reached".into())
}

// The wrapper delegates the real Surface CAS. Its only intervention is after
// the driver's successful READY -> CONSUMING exchange, before it returns.
struct ConsumingPort<'a> {
    inner: RefCell<&'a mut Surface>,
    target: ProcessFaultTarget,
    inject: bool,
    deadline: Instant,
    trace: Trace,
    state: ProcessFaultState,
    handle: RefCell<Option<Box<dyn ProcessFaultHandle>>>,
    failure: RefCell<Option<&'static str>>,
    reached: RefCell<bool>,
}

impl ConsumingPort<'_> {
    fn on_consuming(&self) -> TestResult {
        if *self.reached.borrow() {
            return Err("consuming CAS was observed twice".into());
        }
        let mut state = self.state;
        state.phase = crate::ProcessFaultPhase::PostedConsuming;
        state.reply_state = ControlState::Consuming as u32;
        self.trace
            .borrow_mut()
            .push(ProcessFaultMark::Reached(state));
        *self.reached.borrow_mut() = true;
        if !self.inject {
            return Ok(());
        }
        let seal = crate::FaultSeal {
            trace: Rc::clone(&self.trace),
            deadline: self.deadline,
        };
        let handle = self
            .inner
            .borrow()
            .inject_posted_consuming_fault(self.target, seal)
            .map_err(|()| "consuming fault refused")?;
        *self.handle.borrow_mut() = Some(handle);
        self.observe_consuming(state)
    }

    fn observe_consuming(&self, state: ProcessFaultState) -> TestResult {
        loop {
            if let Some(event) = self
                .inner
                .borrow()
                .posted_fault_event(self.target)
                .map_err(|()| "consuming fault event mismatched")?
            {
                let held = self.handle.borrow();
                let handle = held.as_ref().ok_or("consuming fault handle missing")?;
                let identity = handle.identity();
                let code = handle
                    .exit_code()
                    .map_err(|()| "consuming exit query failed")?
                    .ok_or("consuming exit still pending")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                let expected = match self.target {
                    ProcessFaultTarget::Renderer => ProcessFaultMark::MainRendererExited,
                    ProcessFaultTarget::Browser => ProcessFaultMark::OwnBrowserExited,
                };
                if self.trace.borrow().as_slice()
                    != [
                        ProcessFaultMark::Reached(state),
                        ProcessFaultMark::Selected(identity),
                        ProcessFaultMark::TerminationCall,
                        expected,
                        ProcessFaultMark::ExitCode(0x535),
                    ]
                {
                    return Err("consuming fault evidence incomplete".into());
                }
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("consuming event timed out".into());
            }
            readiness::pump(&self.inner.borrow())?;
        }
    }
}

impl OwnerWebSurface for ConsumingPort<'_> {
    fn open(
        &mut self,
        spec: &SurfaceSpec,
    ) -> Poll<Result<pos_owner_bridge::ProcessIdentity, pos_owner_bridge::SurfaceError>> {
        self.inner.borrow_mut().open(spec)
    }
    fn navigate(
        &mut self,
    ) -> Poll<Result<pos_owner_bridge::NavigationId, pos_owner_bridge::SurfaceError>> {
        self.inner.borrow_mut().navigate()
    }
    fn create_and_write(
        &mut self,
        request: &pos_owner_bridge::RequestImage,
        header: &[u8; 64],
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().create_and_write(request, header)
    }
    fn post(
        &mut self,
        guard: &pos_owner_bridge::PostGuard,
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().post(guard)
    }
    fn reply_load_state(&self) -> Result<u32, pos_owner_bridge::SurfaceError> {
        self.inner.borrow().reply_load_state()
    }
    fn reply_compare_exchange(
        &self,
        current: u32,
        new: u32,
    ) -> Result<bool, pos_owner_bridge::SurfaceError> {
        let won = self.inner.borrow().reply_compare_exchange(current, new)?;
        if won
            && current == ControlState::Ready as u32
            && new == ControlState::Consuming as u32
            && self.on_consuming().is_err()
        {
            *self.failure.borrow_mut() = Some("consuming fault evidence failed");
        }
        Ok(won)
    }
    fn reply_copy(
        &self,
        out: &mut pos_owner_bridge::ReplyImage,
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow().reply_copy(out)
    }
    fn zero_close_buffers(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().zero_close_buffers()
    }
    fn close_controller(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().close_controller()
    }
    fn take_event(&mut self) -> Option<pos_owner_bridge::SurfaceEvent> {
        self.inner.borrow_mut().take_event()
    }
    fn finish(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().finish()
    }
}

fn run_consuming_cases(runtime: &Path, root: &Path) -> TestResult {
    for (number, target) in [
        (0x74, ProcessFaultTarget::Renderer),
        (0x76, ProcessFaultTarget::Browser),
    ] {
        let control = run_consuming(runtime, root, number, target, false)?;
        let fault = run_consuming(runtime, root, number + 1, target, true)?;
        assert_eq!(
            control, fault,
            "consuming control and fault reached different states"
        );
    }
    Ok(())
}

impl Fixture {
    fn drive_consuming(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> DriveResult {
        loop {
            if self.reached.is_none()
                && driver.first_receipt_at().is_some()
                && self
                    .surface
                    .reply_load_state()
                    .map_err(|_| "consuming reply read failed")?
                    == ControlState::Ready as u32
            {
                let state = self
                    .surface
                    .posted_ready_fault_state(driver.posts())
                    .map_err(|()| "pre-consuming state unavailable")?;
                let deadline = self
                    .deadline
                    .min(driver.next_wake().ok_or("consuming deadline missing")?);
                if Instant::now() >= deadline {
                    return Err("consuming fault point expired".into());
                }
                let step = self.consuming_step(driver, target, inject, state, deadline)?;
                match step {
                    Step::Finished(result) => return Ok(result),
                    Step::Done => return Err("consuming driver ended without result".into()),
                    Step::Pending => readiness::pump(&self.surface)?,
                }
            } else {
                let step = driver.step(&mut readiness::env(
                    &mut self.surface,
                    &mut self.loopback,
                    &mut self.store,
                ));
                match step {
                    Step::Finished(result) => return Ok(result),
                    Step::Done => return Err("consuming driver ended without result".into()),
                    Step::Pending => readiness::pump(&self.surface)?,
                }
            }
        }
    }

    fn consuming_step(
        &mut self,
        driver: &mut CeremonyDriver,
        target: ProcessFaultTarget,
        inject: bool,
        state: ProcessFaultState,
        deadline: Instant,
    ) -> Result<Step, Box<dyn std::error::Error>> {
        let (attempt, handle, failure, reached) = {
            let mut port = ConsumingPort {
                inner: RefCell::new(&mut self.surface),
                target,
                inject,
                deadline,
                trace: Rc::clone(&self.trace),
                state,
                handle: RefCell::new(None),
                failure: RefCell::new(None),
                reached: RefCell::new(false),
            };
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                driver.step(&mut pos_owner_bridge::ceremony::driver::StepEnv {
                    surface: &mut port,
                    clock: &SystemClock,
                    loopback: &mut self.loopback,
                    store: &mut self.store,
                })
            }));
            let handle = port.handle.borrow_mut().take();
            let failure = port.failure.borrow_mut().take();
            let reached = *port.reached.borrow();
            (attempt, handle, failure, reached)
        };
        self.handle = handle;
        let step = match attempt {
            Ok(step) => step,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        if let Some(error) = failure {
            return Err(error.into());
        }
        if !reached {
            return Ok(step);
        }
        let mut state = state;
        state.phase = crate::ProcessFaultPhase::PostedConsuming;
        state.reply_state = ControlState::Consuming as u32;
        self.reached = Some(state);
        self.evidence_complete = true;
        if !self.surface.fault_owners_retained() {
            return Err("consuming owners missing".into());
        }
        self.check_blocked_admission()?;
        Ok(step)
    }
}

fn run_consuming(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<ProcessFaultState, Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(
        runtime,
        root,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_consuming(&mut driver, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let accepted = result.is_ok();
    let expected_prf = has_synthetic_success_prf(&driver);
    let prf_clear = driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let slot_clear = driver.request_clear();
    let complete = fixture.evidence_complete;
    let state = fixture.reached;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
    check_final_process_failures(inject.then_some(target))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !complete
        || !slot_clear
        || !native_zeroed
        || !plan_wiped
        || (inject && (accepted || !prf_clear))
        || (!inject && (!accepted || !expected_prf))
    {
        return Err("consuming result, wipe, or evidence was not established".into());
    }
    state.ok_or_else(|| "consuming state was not reached".into())
}

// Both ports borrow the same real Surface; the driver's open call has returned
// before it calls the record store, so their RefCell borrows never overlap.
struct SharedSurfacePort<'a, 's> {
    inner: &'a RefCell<&'s mut Surface>,
}

impl OwnerWebSurface for SharedSurfacePort<'_, '_> {
    fn open(
        &mut self,
        spec: &SurfaceSpec,
    ) -> Poll<Result<pos_owner_bridge::ProcessIdentity, pos_owner_bridge::SurfaceError>> {
        self.inner.borrow_mut().open(spec)
    }
    fn navigate(
        &mut self,
    ) -> Poll<Result<pos_owner_bridge::NavigationId, pos_owner_bridge::SurfaceError>> {
        self.inner.borrow_mut().navigate()
    }
    fn create_and_write(
        &mut self,
        request: &pos_owner_bridge::RequestImage,
        header: &[u8; 64],
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().create_and_write(request, header)
    }
    fn post(
        &mut self,
        guard: &pos_owner_bridge::PostGuard,
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().post(guard)
    }
    fn reply_load_state(&self) -> Result<u32, pos_owner_bridge::SurfaceError> {
        self.inner.borrow().reply_load_state()
    }
    fn reply_compare_exchange(
        &self,
        current: u32,
        new: u32,
    ) -> Result<bool, pos_owner_bridge::SurfaceError> {
        self.inner.borrow().reply_compare_exchange(current, new)
    }
    fn reply_copy(
        &self,
        out: &mut pos_owner_bridge::ReplyImage,
    ) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow().reply_copy(out)
    }
    fn zero_close_buffers(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().zero_close_buffers()
    }
    fn close_controller(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().close_controller()
    }
    fn take_event(&mut self) -> Option<pos_owner_bridge::SurfaceEvent> {
        self.inner.borrow_mut().take_event()
    }
    fn finish(&mut self) -> Result<(), pos_owner_bridge::SurfaceError> {
        self.inner.borrow_mut().finish()
    }
}

struct BeforeRecordStore<'a, 's> {
    inner: &'a mut WindowsCleanupStore,
    surface: &'a RefCell<&'s mut Surface>,
    inject: bool,
    target: ProcessFaultTarget,
    presence: Option<crate::RendererPresence>,
    deadline: Instant,
    trace: Trace,
    handle: Option<Box<dyn ProcessFaultHandle>>,
    failure: Option<&'static str>,
    reached: bool,
    written: bool,
    generation: u32,
    posts: u8,
    ceremony_id: CeremonyId,
}

impl BeforeRecordStore<'_, '_> {
    fn on_write(&mut self, record: &[u8]) -> TestResult {
        if self.reached {
            return Err("record write observed twice".into());
        }
        if Instant::now() >= self.deadline {
            return Err("pre-record point expired".into());
        }
        let browser = self
            .surface
            .borrow_mut()
            .before_record_fault_state()
            .map_err(|()| "pre-record ownership indeterminate")?;
        let decoded = pos_owner_bridge_codec::decode_cleanup_record(record)
            .map_err(|_| "pre-record bytes failed to decode")?;
        if self.generation != 1
            || self.posts != 0
            || decoded.ceremony_id() != self.ceremony_id
            || decoded.folder_name() != pos_owner_bridge::folder_name(&self.ceremony_id)
            || decoded.browser_pid() != browser.browser_pid
            || decoded.creation_filetime() != browser.creation_filetime
            || decoded.image_path_sha256() != browser.image_path_sha256
        {
            return Err("pre-record proposed identity or driver state mismatched".into());
        }
        if self.target == ProcessFaultTarget::Renderer {
            let presence = self
                .surface
                .borrow()
                .early_renderer_presence()
                .map_err(|()| "pre-record renderer snapshot unavailable or ambiguous")?;
            if self
                .surface
                .borrow_mut()
                .before_record_fault_state()
                .map_err(|()| "pre-record state advanced")?
                != browser
            {
                return Err("pre-record browser changed during renderer discovery".into());
            }
            self.presence = Some(presence);
        }
        let mark = ProcessFaultMark::BeforeRecord {
            generation: 1,
            record_count: 0,
        };
        self.trace.borrow_mut().push(mark);
        if let Some(presence) = self.presence {
            self.trace
                .borrow_mut()
                .push(ProcessFaultMark::RendererPresence(presence));
        }
        self.reached = true;
        if self.inject && self.presence != Some(crate::RendererPresence::Absent) {
            let seal = crate::FaultSeal {
                trace: Rc::clone(&self.trace),
                deadline: self.deadline,
            };
            self.handle = Some(
                self.surface
                    .borrow_mut()
                    .inject_before_record_fault(self.target, seal)
                    .map_err(|()| "pre-record fault refused")?,
            );
            self.observe_before_record(browser, mark)?;
        }
        let owners_before = self.surface.borrow_mut().before_record_owners_retained();
        let blocked = matches!(
            self.surface.borrow_mut().open(&competing_spec()),
            Poll::Ready(Err(_))
        );
        let owners_after = self.surface.borrow_mut().before_record_owners_retained();
        if !owners_before || !blocked || !owners_after {
            return Err("pre-record owners or blocked admission missing".into());
        }
        Ok(())
    }

    fn observe_before_record(
        &self,
        browser: pos_owner_bridge::ProcessIdentity,
        first: ProcessFaultMark,
    ) -> TestResult {
        loop {
            if let Some(event) = self
                .surface
                .borrow()
                .posted_fault_event(self.target)
                .map_err(|()| "pre-record browser exit mismatched")?
            {
                let handle = self
                    .handle
                    .as_ref()
                    .ok_or("pre-record fault handle missing")?;
                let code = handle
                    .exit_code()
                    .map_err(|()| "pre-record exit query failed")?
                    .ok_or("pre-record process exit pending")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                let selected = handle.identity();
                let mut expected = vec![first];
                if let Some(presence) = self.presence {
                    expected.push(ProcessFaultMark::RendererPresence(presence));
                }
                expected.extend([
                    ProcessFaultMark::Selected(selected),
                    ProcessFaultMark::TerminationCall,
                    match self.target {
                        ProcessFaultTarget::Browser => ProcessFaultMark::OwnBrowserExited,
                        ProcessFaultTarget::Renderer => ProcessFaultMark::MainRendererExited,
                    },
                    ProcessFaultMark::ExitCode(0x535),
                ]);
                if (self.target == ProcessFaultTarget::Browser && selected != browser)
                    || self.trace.borrow().as_slice() != expected.as_slice()
                {
                    return Err("pre-record fault evidence incomplete".into());
                }
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("pre-record browser exit timed out".into());
            }
            readiness::pump(&self.surface.borrow())?;
        }
    }
}

impl CleanupStore for BeforeRecordStore<'_, '_> {
    fn write_record(&mut self, record: &[u8]) -> Result<(), pos_owner_bridge::CleanupError> {
        if self.on_write(record).is_err() {
            self.failure = Some("pre-record fault evidence failed");
        }
        // Always return the result of the real durable store operation.
        let result = self.inner.write_record(record);
        self.written = result.is_ok();
        if self.written {
            self.trace
                .borrow_mut()
                .push(ProcessFaultMark::RecordWritten);
        }
        result
    }
    fn delete_record(&mut self, record: &[u8]) -> Result<(), pos_owner_bridge::CleanupError> {
        self.inner.delete_record(record)
    }
    fn records(&mut self) -> Result<Vec<Vec<u8>>, pos_owner_bridge::CleanupError> {
        self.inner.records()
    }
    fn folders(&mut self) -> Result<Vec<String>, pos_owner_bridge::CleanupError> {
        self.inner.folders()
    }
    fn remove_folder(&mut self, folder: &str) -> Result<(), pos_owner_bridge::CleanupError> {
        self.inner.remove_folder(folder)
    }
}

fn run_before_record_cases(runtime: &Path, root: &Path) -> TestResult {
    let control = run_before_record(runtime, root, 0x78, ProcessFaultTarget::Browser, false)?;
    let fault = run_before_record(runtime, root, 0x79, ProcessFaultTarget::Browser, true)?;
    assert_eq!(
        control, fault,
        "pre-record browser control and fault reached different states"
    );
    Ok(())
}

#[test]
fn native_before_record_renderer_classification_and_fault() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let control = run_before_record(
        Path::new(&runtime),
        &root.0,
        0x7a,
        ProcessFaultTarget::Renderer,
        false,
    )?;
    let fault = run_before_record(
        Path::new(&runtime),
        &root.0,
        0x7b,
        ProcessFaultTarget::Renderer,
        true,
    )?;
    assert_eq!(
        control, fault,
        "pre-record renderer control and fault reached different states or observations"
    );
    root.remove()
}

impl Fixture {
    fn before_record_step(
        &mut self,
        driver: &mut CeremonyDriver,
        ceremony_id: CeremonyId,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> Result<Step, Box<dyn std::error::Error>> {
        let (attempt, handle, failure, reached, written, presence) = {
            let shared = RefCell::new(&mut self.surface);
            let mut surface = SharedSurfacePort { inner: &shared };
            let mut store = BeforeRecordStore {
                inner: &mut self.store,
                surface: &shared,
                inject,
                target,
                presence: None,
                deadline: self.deadline,
                trace: Rc::clone(&self.trace),
                handle: None,
                failure: None,
                reached: false,
                written: false,
                generation: driver.generation(),
                posts: driver.posts(),
                ceremony_id,
            };
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                driver.step(&mut pos_owner_bridge::ceremony::driver::StepEnv {
                    surface: &mut surface,
                    clock: &SystemClock,
                    loopback: &mut self.loopback,
                    store: &mut store,
                })
            }));
            let handle = store.handle.take();
            let failure = store.failure;
            let reached = store.reached;
            let written = store.written;
            let presence = store.presence;
            (attempt, handle, failure, reached, written, presence)
        };
        self.handle = handle;
        let step = match attempt {
            Ok(step) => step,
            Err(payload) => std::panic::resume_unwind(payload),
        };
        if let Some(error) = failure {
            return Err(error.into());
        }
        if reached {
            self.early_presence = presence;
            if !written
                || self.trace.borrow().last() != Some(&ProcessFaultMark::RecordWritten)
                || self.store.records()?.len() != 1
            {
                return Err("real pre-record durable write was not established".into());
            }
            self.evidence_complete = true;
        }
        Ok(step)
    }

    fn drive_before_record(
        &mut self,
        driver: &mut CeremonyDriver,
        ceremony_id: CeremonyId,
        target: ProcessFaultTarget,
        inject: bool,
    ) -> DriveResult {
        let mut cancelled = false;
        loop {
            let step = if self.evidence_complete {
                driver.step(&mut readiness::env(
                    &mut self.surface,
                    &mut self.loopback,
                    &mut self.store,
                ))
            } else {
                self.before_record_step(driver, ceremony_id, target, inject)?
            };
            if self.evidence_complete && self.handle.is_none() && !cancelled {
                self.surface.controller_lost();
                cancelled = true;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("pre-record driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_before_record(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    inject: bool,
) -> Result<(ProcessFaultMark, Option<crate::RendererPresence>), Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let ceremony_id = CeremonyId::from_bytes([number; 16]);
    let mut driver = readiness::new_driver(ceremony_id, Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_before_record(&mut driver, ceremony_id, target, inject)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let mark = fixture.trace.borrow().first().copied();
    let presence = fixture.early_presence;
    let actual_fault = fixture.handle.is_some();
    let _written = writeln!(std::io::stderr(), "NATIVE_EARLY_RENDERER phase=before_record presence={presence:?} declared_fault={inject} actual_fault={actual_fault}");
    let finish = FailureFinish {
        target,
        inject,
        actual_fault,
        native_zeroed: None,
        message: "pre-record failure, wipe, or evidence was not established",
    };
    fixture.finish_failed_case(driver, result, failure, finish)?;
    Ok((mark.ok_or("pre-record point was not reached")?, presence))
}

#[derive(Clone, Copy, Debug)]
enum EarlyRendererPhase {
    Navigating,
    AwaitingLoad,
}

#[test]
fn native_early_renderer_classification_and_faults() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_early_renderer_cases(Path::new(&runtime), &root.0)?;
    root.remove()
}

fn run_early_renderer_cases(runtime: &Path, root: &Path) -> TestResult {
    for (number, phase) in [
        (0x80, EarlyRendererPhase::Navigating),
        (0x82, EarlyRendererPhase::AwaitingLoad),
    ] {
        let control = run_early_renderer(runtime, root, number, phase, false)?;
        let fault = run_early_renderer(runtime, root, number + 1, phase, true)?;
        assert_eq!(
            control, fault,
            "early renderer control and fault reached different states or observations"
        );
    }
    Ok(())
}

impl Fixture {
    fn early_renderer_state(
        &mut self,
        driver: &CeremonyDriver,
        phase: EarlyRendererPhase,
    ) -> Result<Option<ProcessFaultMark>, Box<dyn std::error::Error>> {
        match phase {
            EarlyRendererPhase::Navigating if self.surface.navigating_fault_ready() => self
                .surface
                .navigating_fault_state(driver.generation(), driver.posts())
                .map(Some)
                .map_err(|()| "renderer navigation state indeterminate".into()),
            EarlyRendererPhase::AwaitingLoad if self.surface.awaiting_load_fault_ready() => self
                .surface
                .awaiting_load_fault_state(driver.generation(), driver.posts())
                .map(Some)
                .map_err(|()| "renderer load state indeterminate".into()),
            _ => Ok(None),
        }
    }

    fn drive_early_renderer(
        &mut self,
        driver: &mut CeremonyDriver,
        phase: EarlyRendererPhase,
        inject: bool,
    ) -> Result<(Result<Verified, BridgeError>, ProcessFaultMark), Box<dyn std::error::Error>> {
        let mut reached = None;
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if reached.is_none() && matches!(&step, Step::Pending) {
                if let Some(mark) = self.early_renderer_state(driver, phase)? {
                    let presence = self
                        .surface
                        .early_renderer_presence()
                        .map_err(|()| "renderer snapshot unavailable or ambiguous")?;
                    // Recheck the phase after the complete pair of snapshots.
                    if self.early_renderer_state(driver, phase)? != Some(mark) {
                        return Err("renderer phase advanced during discovery".into());
                    }
                    self.early_presence = Some(presence);
                    self.trace
                        .borrow_mut()
                        .extend([mark, ProcessFaultMark::RendererPresence(presence)]);
                    if inject && presence == crate::RendererPresence::Unique {
                        let seal = crate::FaultSeal {
                            trace: Rc::clone(&self.trace),
                            deadline: self.deadline,
                        };
                        self.handle = Some(
                            match phase {
                                EarlyRendererPhase::Navigating => self
                                    .surface
                                    .inject_navigating_fault(ProcessFaultTarget::Renderer, seal),
                                EarlyRendererPhase::AwaitingLoad => self
                                    .surface
                                    .inject_awaiting_load_fault(ProcessFaultTarget::Renderer, seal),
                            }
                            .map_err(|()| "early renderer fault refused")?,
                        );
                        self.observe_early_renderer(mark)?;
                    } else {
                        self.evidence_complete = true;
                    }
                    let owners = match phase {
                        EarlyRendererPhase::Navigating => {
                            self.surface.navigating_fault_owners_retained()
                        }
                        EarlyRendererPhase::AwaitingLoad => {
                            self.surface.awaiting_load_fault_owners_retained()
                        }
                    };
                    if !self.evidence_complete
                        || !owners
                        || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    {
                        return Err("early renderer owners or blocked admission missing".into());
                    }
                    let owners_after = match phase {
                        EarlyRendererPhase::Navigating => {
                            self.surface.navigating_fault_owners_retained()
                        }
                        EarlyRendererPhase::AwaitingLoad => {
                            self.surface.awaiting_load_fault_owners_retained()
                        }
                    };
                    if !owners_after {
                        return Err("early renderer owners changed during blocked admission".into());
                    }
                    if self.handle.is_none() {
                        self.surface.controller_lost();
                    }
                    reached = Some(mark);
                }
            }
            match step {
                Step::Finished(result) => {
                    return Ok((result, reached.ok_or("early renderer phase not reached")?))
                }
                Step::Done => return Err("early renderer driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn observe_early_renderer(&mut self, first: ProcessFaultMark) -> TestResult {
        loop {
            if let Some(event) = self
                .surface
                .posted_fault_event(ProcessFaultTarget::Renderer)
                .map_err(|()| "early renderer event mismatched")?
            {
                let held = self
                    .handle
                    .as_ref()
                    .ok_or("early renderer handle missing")?;
                let identity = held.identity();
                let code = held
                    .exit_code()
                    .map_err(|()| "early renderer exit query failed")?
                    .ok_or("early renderer exit pending")?;
                self.trace
                    .borrow_mut()
                    .extend([event, ProcessFaultMark::ExitCode(code)]);
                if self.trace.borrow().as_slice()
                    != [
                        first,
                        ProcessFaultMark::RendererPresence(crate::RendererPresence::Unique),
                        ProcessFaultMark::Selected(identity),
                        ProcessFaultMark::TerminationCall,
                        ProcessFaultMark::MainRendererExited,
                        ProcessFaultMark::ExitCode(0x535),
                    ]
                {
                    return Err("early renderer ordered evidence incomplete".into());
                }
                self.evidence_complete = true;
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("early renderer event timed out".into());
            }
            readiness::pump(&self.surface)?;
        }
    }
}

fn run_early_renderer(
    runtime: &Path,
    root: &Path,
    number: u8,
    phase: EarlyRendererPhase,
    inject: bool,
) -> Result<(ProcessFaultMark, crate::RendererPresence), Box<dyn std::error::Error>> {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_early_renderer(&mut driver, phase, inject)
    }));
    let mut mark = None;
    let attempt = attempt.map(|result| {
        result.map(|(outcome, state)| {
            mark = Some(state);
            outcome
        })
    });
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let presence = fixture.early_presence;
    let actual_fault = fixture.handle.is_some();
    let _written = writeln!(std::io::stderr(), "NATIVE_EARLY_RENDERER phase={phase:?} presence={presence:?} declared_fault={inject} actual_fault={actual_fault}");
    let finish = FailureFinish {
        target: ProcessFaultTarget::Renderer,
        inject,
        actual_fault,
        native_zeroed: None,
        message: "early renderer failure, wipe, or evidence missing",
    };
    fixture.finish_failed_case(driver, result, failure, finish)?;
    Ok((
        mark.ok_or("early renderer state missing")?,
        presence.ok_or("early renderer snapshot missing")?,
    ))
}

#[derive(Clone, Copy)]
enum EnvironmentCase {
    HeldResult,
    LateInvocation,
}

fn environment_callback_order(
    order: &[crate::NativeCallbackMoment],
    case: EnvironmentCase,
) -> bool {
    use crate::NativeCallbackMoment::{DriverTimeout, EnvironmentCompletion};
    let mut callback = None;
    let mut timeout = None;
    for (index, moment) in order.iter().enumerate() {
        match moment {
            EnvironmentCompletion(true) if callback.is_none() => callback = Some(index),
            DriverTimeout if timeout.is_none() => timeout = Some(index),
            _ => return false,
        }
    }
    match (callback, timeout, case) {
        (Some(callback), Some(timeout), EnvironmentCase::HeldResult) => callback < timeout,
        (Some(callback), Some(timeout), EnvironmentCase::LateInvocation) => timeout < callback,
        _ => false,
    }
}

#[test]
fn environment_order_distinguishes_held_result_from_late_invocation() {
    use crate::NativeCallbackMoment::{DriverTimeout, EnvironmentCompletion, Overflow};
    let held = [EnvironmentCompletion(true), DriverTimeout];
    let late = [DriverTimeout, EnvironmentCompletion(true)];
    assert!(environment_callback_order(
        &held,
        EnvironmentCase::HeldResult
    ));
    assert!(!environment_callback_order(
        &held,
        EnvironmentCase::LateInvocation
    ));
    assert!(environment_callback_order(
        &late,
        EnvironmentCase::LateInvocation
    ));
    assert!(!environment_callback_order(
        &late,
        EnvironmentCase::HeldResult
    ));
    assert!(!environment_callback_order(
        &[DriverTimeout, EnvironmentCompletion(false)],
        EnvironmentCase::LateInvocation
    ));
    assert!(!environment_callback_order(
        &[DriverTimeout, EnvironmentCompletion(true), Overflow],
        EnvironmentCase::LateInvocation
    ));
}

#[test]
fn native_pre_environment_held_completion_and_retirement() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_pre_environment(Path::new(&runtime), 0x7e, EnvironmentCase::HeldResult)
}

#[test]
fn native_pre_environment_late_callback_and_retirement() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_pre_environment(Path::new(&runtime), 0x7f, EnvironmentCase::LateInvocation)
}

fn run_pre_environment(runtime: &Path, number: u8, case: EnvironmentCase) -> TestResult {
    use pos_owner_bridge::LifecycleCode;
    let root = FixtureRoot::new()?;
    let _callback_order = CallbackOrderGuard::arm();
    let mut fixture = Fixture::new(runtime, &root.0, number, FixtureProfile::Pending)?;
    let started = Instant::now();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), started)?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        let initial = driver.step(&mut readiness::env(
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        ));
        let pending = matches!(initial, Step::Pending)
            && fixture.surface.pre_environment_completion() == Ok(None);
        // Dispatch genuine callbacks while leaving the driver unstepped until
        // its original readiness deadline; callback delivery is not held.
        let deadline = started + pos_owner_bridge::ceremony::timing::READINESS;
        let mut pump_failed = false;
        while Instant::now() < deadline {
            if readiness::pump(&fixture.surface).is_err() {
                pump_failed = true;
            }
        }
        let at_deadline = fixture.surface.pre_environment_completion();
        let result = match driver.step(&mut readiness::env(
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        )) {
            Step::Finished(result) => result,
            _ => readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
        };
        crate::Native::record_callback(crate::NativeCallbackMoment::DriverTimeout);
        (result, pending, pump_failed, at_deadline)
    }));
    let (result, pending, pump_failed, at_deadline) = match attempt {
        Ok(observation) => observation,
        Err(_) => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            false,
            true,
            Err(()),
        ),
    };
    let timed_out = matches!(
        &result,
        Err(BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout))
    );
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    // The real failed-opening path retains the callback until it completes.
    retirement::retire(
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
        driver,
        result,
        |_, _, _| {},
    );
    let order = crate::Native::callback_order();
    let ordered = environment_callback_order(&order, case);
    let no_record = fixture.store.records()?.is_empty();
    let retained_orphan = fixture.store.folders()?.len() == 1;
    let idle = fixture.surface.idle();
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("pre-environment factory still shared")?
        .stop()?;
    // No process/exit was established. Preserve the recordless folder for real
    // later recovery; neither an orphan sweep nor remove_dir_all is evidence.
    if !pending
        || pump_failed
        || !timed_out
        || !wiped
        || !ordered
        || !no_record
        || !retained_orphan
        || !idle
    {
        return Err(format!("pre-environment witness failed: pending={pending} completion={at_deadline:?} timeout={timed_out} wiped={wiped} ordered={ordered} no_record={no_record} retained_orphan={retained_orphan} idle={idle}").into());
    }
    Ok(())
}
