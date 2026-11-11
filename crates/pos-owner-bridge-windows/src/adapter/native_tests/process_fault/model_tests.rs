#![cfg(windows)]
#![forbid(unsafe_code)]

//! Modeled process observations exercise the harness's result and trace validation.

use std::cell::RefCell;
use std::io::Write as _;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::listener::FixtureProfile;
use pos_owner_bridge::{
    BridgeError, OwnerWebSurface, ProcessIdentity, SystemClock, UnavailableCode,
};
use pos_owner_bridge_codec::{CeremonyId, ControlState, ImagePathSha256};

use super::{
    fixed_competing_spec, readiness, DriveResult, FailureFinish, Fixture, FixtureRoot, TestResult,
};
use crate::adapter::surface::tests::native::{Creation, Factory};
use crate::adapter::surface::tests::Runtime;
use crate::adapter::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use crate::{
    NativeEvent, NativeFactory, ProcessFaultHandle, ProcessFaultMark, ProcessFaultPhase,
    ProcessFaultState, ProcessFaultTarget, ProcessFaultTopology,
};

const ERROR: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const MODEL_CASE: u8 = 240;

fn fixture(root: &FixtureRoot) -> Result<(Fixture, Rc<Factory>), Box<dyn std::error::Error>> {
    let _logged = writeln!(
        std::io::stderr(),
        "NATIVE_FAULT_MODEL case={MODEL_CASE} process_observation=scripted native_zeroing=scripted"
    );
    let model = Factory::new(Creation::Ready, FakeClock::start());
    let factory: Rc<dyn NativeFactory> = Rc::new(Rc::clone(&model));
    let store = WindowsCleanupStore::open(root.0.clone())?;
    let loopback = SharedLoopback::start_fixture(FixtureProfile::Pending)?;
    let mut surface = Surface::new(
        Rc::clone(&factory),
        Arc::new(Runtime(root.0.clone())),
        root.0.clone(),
        Box::new(loopback.clone()),
        Box::new(store.clone()),
        Box::new(SystemClock),
    )
    .map_err(pos_owner_bridge::SurfaceError::error)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    surface.set_deadline(deadline);
    Ok((
        Fixture {
            number: MODEL_CASE,
            profile: FixtureProfile::Pending,
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
        },
        model,
    ))
}

#[test]
fn modeled_attempt_errors_and_panics_cancel_before_preserving_the_original_failure() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let attempts: [(std::thread::Result<DriveResult>, &str); 2] = [
        (
            Ok(Err("modeled drive failure".into())),
            "modeled drive failure",
        ),
        (
            Err(Box::new("modeled drive panic")),
            "process fault fixture panicked",
        ),
    ];
    for (attempt, expected) in attempts {
        let root = FixtureRoot::new()?;
        let (mut fixture, _model) = fixture(&root)?;
        let mut driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
        assert!(result.is_err());
        assert_eq!(
            failure.as_ref().map(ToString::to_string).as_deref(),
            Some(expected)
        );
        assert!(driver.request_clear());
        assert!(driver.prf().iter().all(|byte| *byte == 0));
        assert!(fixture.surface.idle());
        fixture.retire(driver, result, None)?;
        root.remove()?;
    }
    Ok(())
}

#[test]
fn modeled_completed_attempt_preserves_its_result_without_cancelling() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let mut driver =
        readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
    let calls = model.calls.borrow().clone();
    let (result, failure) = fixture.resolve_attempt(&mut driver, Ok(Ok(Err(ERROR))));
    assert_eq!(result, Err(ERROR));
    assert!(failure.is_none());
    assert_eq!(*model.calls.borrow(), calls);
    assert!(!driver.plan_secrets_clear());
    fixture.retire(driver, result, None)?;
    root.remove()
}

#[test]
fn modeled_failure_finish_checks_evidence_after_retiring_and_preserves_prior_errors() -> TestResult
{
    let _port = crate::Native::fixed_port_fixture();
    for (complete, native_zeroed, failure, expected) in [
        (true, Some(true), None, None),
        (true, None, None, None),
        (false, Some(true), None, Some("modeled evidence missing")),
        (true, Some(false), None, Some("modeled evidence missing")),
        (
            false,
            Some(false),
            Some("original modeled drive error"),
            Some("original modeled drive error"),
        ),
    ] {
        crate::Native::reset_process_failure_observations();
        let root = FixtureRoot::new()?;
        let (mut fixture, _model) = fixture(&root)?;
        let mut driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        let result = readiness::cancel_driver(
            &mut driver,
            &mut fixture.surface,
            &mut fixture.loopback,
            &mut fixture.store,
        );
        fixture.evidence_complete = complete;
        let outcome = fixture.finish_failed_case(
            driver,
            result,
            failure.map(Into::into),
            FailureFinish {
                target: ProcessFaultTarget::Browser,
                inject: false,
                actual_fault: false,
                native_zeroed,
                message: "modeled evidence missing",
            },
        );
        let error = outcome.err().map(|error| error.to_string());
        assert_eq!(
            error
                .as_deref()
                .map(|error| error.split(';').next().unwrap_or_default()),
            expected
        );
        assert!(failure.is_none_or(|original| error.as_deref() == Some(original)));
        root.remove()?;
    }
    Ok(())
}

struct Handle(Result<Option<u32>, ()>);

impl ProcessFaultHandle for Handle {
    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            browser_pid: 42,
            creation_filetime: 1,
            image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
        }
    }

    fn exit_code(&self) -> Result<Option<u32>, ()> {
        self.0
    }
}

#[test]
fn modeled_fault_observer_requires_a_reached_state_and_unexpired_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, _model) = fixture(&root)?;
    assert_eq!(
        fixture
            .observe_fault(ProcessFaultTarget::Browser)
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("pre-fault state disappeared")
    );
    assert_eq!(
        fixture
            .observe_fault_until(
                ProcessFaultTarget::Browser,
                ProcessFaultMark::TerminationCall,
                Instant::now(),
            )
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("native fault event timed out")
    );
    let driver = readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
    fixture.retire(driver, Err(ERROR), None)?;
    root.remove()
}

#[test]
fn modeled_fault_observer_requires_retained_exit_code_and_ordered_trace() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (code, expected) in [
        (Err(()), Some("exit query failed")),
        (Ok(None), Some("exit still pending at native event")),
        (
            Ok(Some(0)),
            Some("ordered native fault evidence is incomplete"),
        ),
        (Ok(Some(0x535)), None),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        let spec = fixed_competing_spec(MODEL_CASE);
        assert!(fixture.surface.open(&spec).is_pending());
        assert!(fixture.surface.open(&spec).is_pending());
        assert!(matches!(fixture.surface.open(&spec), Poll::Ready(Ok(_))));
        let sink = model
            .sink
            .borrow()
            .clone()
            .ok_or("missing modeled event sink")?;
        let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
        let handle = Handle(code);
        let first = ProcessFaultMark::Reached(ProcessFaultState {
            phase: ProcessFaultPhase::PostedReceipt,
            topology: ProcessFaultTopology::SealedSingleViewFrameFree,
            generation: 1,
            reply_state: ControlState::Received as u32,
            record_count: 1,
            posts: 1,
        });
        fixture.trace.borrow_mut().extend([
            first,
            ProcessFaultMark::Selected(handle.identity()),
            ProcessFaultMark::TerminationCall,
        ]);
        fixture.handle = Some(Box::new(handle));
        let outcome = fixture.observe_fault_until(
            ProcessFaultTarget::Browser,
            first,
            Instant::now() + Duration::from_secs(5),
        );
        assert_eq!(
            outcome.err().map(|error| error.to_string()).as_deref(),
            expected
        );
        assert_eq!(fixture.evidence_complete, expected.is_none());
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        drop(sink);
        let driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        fixture.retire(driver, Err(ERROR), None)?;
        root.remove()?;
    }
    Ok(())
}
