#![cfg(windows)]
#![forbid(unsafe_code)]

//! Modeled process observations exercise the harness's result and trace validation.

use std::cell::RefCell;
use std::io::Write as _;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use pos_owner_bridge::ceremony::driver::CeremonyDriver;
use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::listener::FixtureProfile;
use pos_owner_bridge::{
    BridgeError, MonotonicClock, OwnerWebSurface, ProcessIdentity, SystemClock, UnavailableCode,
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

mod pending_opening_tests;

pub(super) fn fixture(
    root: &FixtureRoot,
) -> Result<(Fixture, Rc<Factory>), Box<dyn std::error::Error>> {
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

type DriveStage = fn(&mut Fixture, &mut CeremonyDriver, ProcessFaultTarget, bool) -> DriveResult;

fn assert_drive_error<T>(result: Result<T, Box<dyn std::error::Error>>, expected: &str) {
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some(expected)
    );
}

fn cancelled_driver(
    fixture: &mut Fixture,
) -> Result<(CeremonyDriver, super::CeremonyResult), Box<dyn std::error::Error>> {
    let mut driver =
        readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
    let result = readiness::cancel_driver(
        &mut driver,
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
    );
    assert!(fixture.finished_driver_is_done(&mut driver));
    Ok((driver, result))
}

#[test]
fn modeled_fault_stages_refuse_a_cancelled_driver_without_native_work() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let (mut driver, result) = cancelled_driver(&mut fixture)?;
    let calls = model.calls.borrow().clone();
    let stages: [(DriveStage, &str); 6] = [
        (Fixture::drive, "driver ended without result"),
        (
            Fixture::drive_success_releasing,
            "success driver ended without result",
        ),
        (
            Fixture::drive_posted_empty,
            "empty-reply driver ended without result",
        ),
        (
            Fixture::drive_posted_writing,
            "writing driver ended without result",
        ),
        (
            Fixture::drive_posted_ready,
            "ready driver ended without result",
        ),
        (
            Fixture::drive_consuming,
            "consuming driver ended without result",
        ),
    ];
    for (stage, expected) in stages {
        assert_drive_error(
            stage(
                &mut fixture,
                &mut driver,
                ProcessFaultTarget::Browser,
                false,
            ),
            expected,
        );
    }
    assert_eq!(*model.calls.borrow(), calls);
    assert!(fixture.trace.borrow().is_empty());
    assert!(!fixture.evidence_complete);
    assert!(fixture.surface.idle());
    fixture.retire(driver, result, None)?;
    root.remove()
}

#[test]
fn modeled_creation_and_exit_stages_refuse_a_cancelled_driver() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let ceremony = CeremonyId::from_bytes([MODEL_CASE; 16]);
    let (mut driver, result) = cancelled_driver(&mut fixture)?;
    let calls = model.calls.borrow().clone();
    assert_drive_error(
        fixture.drive_recordless(&mut driver, false),
        "recordless driver ended without result",
    );
    assert_drive_error(
        fixture.drive_success_exit(&mut driver, false),
        "success exit driver ended without result",
    );
    assert_drive_error(
        fixture.drive_awaiting_load(&mut driver, false),
        "awaiting-load driver ended without result",
    );
    assert_drive_error(
        fixture.drive_navigating(&mut driver, false),
        "navigating driver ended without result",
    );
    assert_drive_error(
        fixture.drive_first_opening_browser(&mut driver, false),
        "opening driver ended without result",
    );
    assert_drive_error(
        fixture.drive_posted_retry(
            &mut driver,
            ProcessFaultTarget::Browser,
            crate::RetryPoint::Second,
            false,
        ),
        "retry empty-reply driver ended without result",
    );
    assert_drive_error(
        fixture.drive_before_record(&mut driver, ceremony, ProcessFaultTarget::Browser, false),
        "pre-record driver ended without result",
    );
    assert_drive_error(
        fixture.drive_early_renderer(&mut driver, super::EarlyRendererPhase::Navigating, false),
        "early renderer driver ended without result",
    );
    assert_eq!(*model.calls.borrow(), calls);
    assert!(fixture.trace.borrow().is_empty());
    assert!(!fixture.evidence_complete);
    assert!(fixture.surface.idle());
    fixture.retire(driver, result, None)?;
    root.remove()
}

#[test]
fn modeled_controller_stages_report_a_cancelled_driver_without_new_provenance() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let ceremony = CeremonyId::from_bytes([MODEL_CASE; 16]);
    let (mut driver, result) = cancelled_driver(&mut fixture)?;
    let calls = model.calls.borrow().clone();
    let mut provenance = None;
    let mut failure_stage = None;
    assert_drive_error(
        fixture.drive_fresh_success(&mut driver, ceremony, &mut provenance, &mut failure_stage),
        "fresh success driver ended without result",
    );
    assert!(provenance.is_none());
    assert_eq!(failure_stage, Some("driver_done"));
    let mut lost_blocked = false;
    assert_drive_error(
        fixture.drive_controller_input(&mut driver, false, &mut lost_blocked),
        "controller input did not reach the pending stage",
    );
    assert!(!lost_blocked);
    assert_drive_error(
        fixture.drive_outstanding_controller(&mut driver, &ceremony),
        "controller did not remain pending",
    );
    assert_eq!(*model.calls.borrow(), calls);
    assert!(fixture.trace.borrow().is_empty());
    assert!(!fixture.evidence_complete);
    assert!(fixture.surface.idle());
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

struct TickingClock(FakeClock);

impl MonotonicClock for TickingClock {
    fn now(&self) -> Instant {
        let now = self.0.now();
        // Absent events also advance modeled time and reach the deadline.
        self.0.advance(Duration::from_secs(1));
        now
    }
}

struct Handle {
    code: Result<Option<u32>, ()>,
    clock: FakeClock,
    advance: Duration,
}

impl ProcessFaultHandle for Handle {
    fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            browser_pid: 42,
            creation_filetime: 1,
            image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
        }
    }

    fn exit_code(&self) -> Result<Option<u32>, ()> {
        self.clock.advance(self.advance);
        self.code
    }
}

#[test]
fn modeled_fault_observer_requires_a_reached_state_and_unexpired_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, _model) = fixture(&root)?;
    let clock = TickingClock(FakeClock::start());
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
            .observe_fault_with_clock(
                ProcessFaultTarget::Browser,
                ProcessFaultMark::TerminationCall,
                clock.now(),
                &clock,
            )
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("native fault event timed out")
    );
    crate::Native::reset_process_failure_observations();
    assert_eq!(
        fixture
            .observe_fault_with_clock(
                ProcessFaultTarget::Renderer,
                ProcessFaultMark::TerminationCall,
                clock.now() + Duration::from_secs(5),
                &clock,
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
    for (code, advance, expected) in [
        (Err(()), Duration::ZERO, Some("exit query failed")),
        (
            Ok(None),
            Duration::ZERO,
            Some("exit still pending at native event"),
        ),
        (
            Ok(Some(0)),
            Duration::ZERO,
            Some("ordered native fault evidence is incomplete"),
        ),
        (Ok(Some(0x535)), Duration::ZERO, None),
        (
            Ok(Some(0x535)),
            Duration::from_secs(6),
            Some("native fault event timed out"),
        ),
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
        let clock = TickingClock(FakeClock::start());
        let deadline = clock.now() + Duration::from_secs(5);
        let handle = Handle {
            code,
            clock: clock.0.clone(),
            advance,
        };
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
        let outcome =
            fixture.observe_fault_with_clock(ProcessFaultTarget::Browser, first, deadline, &clock);
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

#[test]
fn modeled_exit_fault_rejects_duplicate_own_exit_before_querying_handle() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
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
    let _first = sink.event(NativeEvent::BrowserExited { pid: 42 });
    let _duplicate = sink.event(NativeEvent::BrowserExited { pid: 42 });
    let clock = TickingClock(FakeClock::start());
    let deadline = clock.now() + Duration::from_secs(5);
    fixture.handle = Some(Box::new(Handle {
        code: Ok(Some(0x535)),
        clock: clock.0.clone(),
        advance: Duration::from_secs(6),
    }));
    let first = ProcessFaultMark::ReachedExit(crate::ProcessExitState {
        generation: 1,
        record_count: 1,
    });
    let before = clock.0.now();
    let error = fixture
        .observe_fault_with_clock(ProcessFaultTarget::Browser, first, deadline, &clock)
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error.as_deref(),
        Some("exit event was not the unique matching callback")
    );
    assert_eq!(clock.0.now() - before, Duration::from_secs(1));
    assert!(!fixture.evidence_complete);
    assert!(fixture.trace.borrow().is_empty());
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    drop(sink);
    let driver = readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
    fixture.retire(driver, Err(ERROR), None)?;
    root.remove()
}

#[test]
fn modeled_exit_control_requires_unique_callback_zero_status_and_live_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (case, status, duplicate, expired, expected) in [
        ("matching", Ok(Some(0)), false, false, None),
        (
            "nonzero",
            Ok(Some(1)),
            false,
            false,
            Some("control exit code was not zero"),
        ),
        (
            "duplicate",
            Ok(Some(0)),
            true,
            false,
            Some("control exit was not the unique matching callback"),
        ),
        (
            "expired",
            Ok(Some(0)),
            false,
            true,
            Some("control exit timed out"),
        ),
        (
            "query failed",
            Err(()),
            false,
            false,
            Some("control exit query failed"),
        ),
        (
            "status pending",
            Ok(None),
            false,
            false,
            Some("control exit code was not zero"),
        ),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        let spec = fixed_competing_spec(MODEL_CASE);
        assert!(fixture.surface.open(&spec).is_pending(), "case {case}");
        assert!(fixture.surface.open(&spec).is_pending(), "case {case}");
        assert!(
            matches!(fixture.surface.open(&spec), Poll::Ready(Ok(_))),
            "case {case}"
        );
        let sink = model
            .sink
            .borrow()
            .clone()
            .ok_or("missing modeled event sink")?;
        let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
        if duplicate {
            let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
        }
        fixture.handle = Some(Box::new(Handle {
            code: status,
            clock: FakeClock::start(),
            advance: Duration::ZERO,
        }));
        let deadline = if expired {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(5)
        };
        let error = fixture
            .observe_exit_control(deadline)
            .err()
            .map(|error| error.to_string());
        assert_eq!(error.as_deref(), expected, "case {case}");
        assert_eq!(fixture.evidence_complete, expected.is_none(), "case {case}");
        if expected.is_none() {
            assert_eq!(
                *fixture.trace.borrow(),
                [
                    ProcessFaultMark::OwnBrowserExited,
                    ProcessFaultMark::ExitCode(0)
                ],
                "case {case}"
            );
        } else {
            assert!(fixture.trace.borrow().is_empty(), "case {case}");
        }
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
