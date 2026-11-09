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
    BufferSlot, NativeFactory, NativeZeroObservation, ProcessFaultHandle, ProcessFaultMark,
    ProcessFaultState, ProcessFaultTarget,
};

type Trace = Rc<RefCell<Vec<ProcessFaultMark>>>;

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
    evidence_complete: bool,
    deadline: Instant,
}

impl Fixture {
    fn new(
        runtime_path: &Path,
        root: &Path,
        number: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = root.join(format!("process-fault-{number}"));
        crate::create_private_directory(&root)?;
        let runtime = Arc::new(crate::verify_fixed_runtime(runtime_path, &root)?);
        let factory: Rc<dyn NativeFactory> = Rc::new(crate::Native::owner_factory()?);
        let store = WindowsCleanupStore::open(root.clone())?;
        let loopback = SharedLoopback::start_fixture(FixtureProfile::Pending)?;
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
            let seal = crate::FaultSeal(Rc::clone(&self.trace));
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
        // Use a different real ceremony on the same Surface while the original
        // owners and durable record are still unresolved.
        let ceremony_id = CeremonyId::from_bytes([0x7f; 16]);
        let attempted = SurfaceSpec {
            ceremony_id,
            folder_name: pos_owner_bridge::folder_name(&ceremony_id),
            owner_window: None,
        };
        if !matches!(self.surface.open(&attempted), Poll::Ready(Err(_)))
            || !self.surface.fault_owners_retained()
        {
            return Err("a competing Surface opening was not blocked".into());
        }
        Ok(())
    }

    fn observe_fault(&mut self, target: ProcessFaultTarget) -> TestResult {
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
                let state = self.reached.ok_or("pre-fault state disappeared")?;
                if self.trace.borrow().as_slice()
                    != [
                        ProcessFaultMark::Reached(state),
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
        assert!(self.store.folders()?.is_empty());
        drop(self.store);
        Rc::get_mut(&mut self.factory)
            .ok_or("fault factory still shared")?
            .stop()?;
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
    let mut fixture = Fixture::new(runtime, root, number)?;
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
    // Record wipe evidence before moving the driver to its retirement owner.
    // A normal plan is dropped at driver consumption; only a quarantined plan
    // is required to have its own secrets wiped immediately.
    let slot_wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped_if_quarantined =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    let error = result.as_ref().err().copied();
    let reached = fixture.reached;
    let complete_before_cleanup = fixture.evidence_complete;
    let failures = crate::Native::process_failure_observations();
    let native_zeroed = native_zeroing_observed(&crate::Native::take_native_zero_observations());
    fixture.retire(driver, result)?;
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
