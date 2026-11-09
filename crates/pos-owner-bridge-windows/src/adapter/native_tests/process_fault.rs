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

fn competing_spec() -> SurfaceSpec {
    let ceremony_id = CeremonyId::from_bytes([0x7f; 16]);
    SurfaceSpec {
        ceremony_id,
        folder_name: pos_owner_bridge::folder_name(&ceremony_id),
        owner_window: None,
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
    root.remove()
}

struct Fixture {
    surface: Surface,
    loopback: SharedLoopback,
    store: WindowsCleanupStore,
    factory: Rc<dyn NativeFactory>,
    trace: Trace,
    handle: Option<Box<dyn ProcessFaultHandle>>,
    reached: Option<ProcessFaultState>,
    exit_reached: Option<ProcessExitState>,
    evidence_complete: bool,
    deadline: Instant,
}

impl Fixture {
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
            surface,
            loopback,
            store,
            factory,
            trace: Rc::new(RefCell::new(Vec::new())),
            handle: None,
            reached: None,
            exit_reached: None,
            evidence_complete: false,
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
            Some("process fault fixture panicked".into()),
        ),
    };
    let slot_wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped_if_quarantined =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let error = result.as_ref().err().copied();
    let reached = fixture.reached;
    let complete_before_cleanup = fixture.evidence_complete;
    let failures = crate::Native::process_failure_observations();
    let native_zeroed = native_zeroing_observed(&crate::Native::take_native_zero_observations());
    fixture.retire(driver, result, None)?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !complete_before_cleanup {
        return Err("fault evidence was not established before cleanup".into());
    }
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
                Some(true) => return Ok(()),
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
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_recordless(&mut driver, inject)
    }));
    let (result, failure) = match attempt {
        Ok(Ok(result)) => (result, None),
        Ok(Err(error)) => (
            {
                fixture.retain_recordless_until_exit();
                readiness::cancel_driver(
                    &mut driver,
                    &mut fixture.surface,
                    &mut fixture.loopback,
                    &mut fixture.store,
                )
            },
            Some(error),
        ),
        Err(_) => (
            {
                fixture.retain_recordless_until_exit();
                readiness::cancel_driver(
                    &mut driver,
                    &mut fixture.surface,
                    &mut fixture.loopback,
                    &mut fixture.store,
                )
            },
            Some("recordless fault fixture panicked".into()),
        ),
    };
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
            Some("successful release fixture panicked".into()),
        ),
    };
    let verified = result.is_ok() && has_synthetic_success_prf(&driver) && driver.request_clear();
    let reached = fixture.reached;
    let complete = fixture.evidence_complete;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
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
            Some("successful exit fixture panicked".into()),
        ),
    };
    let verified = result.is_ok() && has_synthetic_success_prf(&driver) && driver.request_clear();
    let reached = fixture.exit_reached;
    let complete = fixture.evidence_complete;
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
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
