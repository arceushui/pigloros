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

#[test]
fn modeled_consuming_and_pre_record_observers_enforce_their_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (boundary, advance, accepted) in [
        (true, Duration::ZERO, false),
        (false, Duration::from_secs(6), false),
        (false, Duration::ZERO, true),
    ] {
        for consuming in [true, false] {
            consuming_or_pre_record_deadline_case(boundary, advance, accepted, consuming)?;
        }
    }
    Ok(())
}

fn consuming_or_pre_record_deadline_case(
    boundary: bool,
    advance: Duration,
    accepted: bool,
    consuming: bool,
) -> TestResult {
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let selected = fixed_competing_spec(MODEL_CASE);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(matches!(
        fixture.surface.open(&selected),
        Poll::Ready(Ok(_))
    ));
    let sink = model.sink.borrow().clone().ok_or("missing sink")?;
    sink.event(NativeEvent::BrowserExited { pid: 42 });
    let clock = TickingClock(FakeClock::start());
    let deadline = clock.0.now()
        + if boundary {
            Duration::ZERO
        } else {
            Duration::from_secs(5)
        };
    let handle = Handle {
        code: Ok(Some(0x535)),
        clock: clock.0.clone(),
        advance,
    };
    let browser = handle.identity();
    let state = ProcessFaultState {
        phase: ProcessFaultPhase::PostedConsuming,
        topology: ProcessFaultTopology::SealedSingleViewFrameFree,
        generation: 1,
        reply_state: ControlState::Consuming as u32,
        record_count: 1,
        posts: 1,
    };
    let first = if consuming {
        ProcessFaultMark::Reached(state)
    } else {
        ProcessFaultMark::BeforeRecord {
            generation: 1,
            record_count: 0,
        }
    };
    fixture.trace.borrow_mut().extend([
        first,
        ProcessFaultMark::Selected(browser),
        ProcessFaultMark::TerminationCall,
    ]);
    let result = if consuming {
        let port = super::ConsumingPort {
            inner: RefCell::new(&mut fixture.surface),
            target: ProcessFaultTarget::Browser,
            inject: true,
            deadline,
            trace: Rc::clone(&fixture.trace),
            state,
            handle: RefCell::new(Some(Box::new(handle))),
            failure: RefCell::new(None),
            reached: RefCell::new(true),
        };
        port.observe_consuming_with_clock(state, &clock)
    } else {
        let shared = RefCell::new(&mut fixture.surface);
        let store = super::BeforeRecordStore {
            inner: &mut fixture.store,
            surface: &shared,
            inject: true,
            target: ProcessFaultTarget::Browser,
            presence: None,
            deadline,
            trace: Rc::clone(&fixture.trace),
            handle: Some(Box::new(handle)),
            failure: None,
            reached: true,
            written: false,
            generation: 1,
            posts: 0,
            ceremony_id: CeremonyId::from_bytes([MODEL_CASE; 16]),
        };
        store.observe_before_record_with_clock(browser, first, &clock)
    };
    assert_eq!(result.is_ok(), accepted);
    assert_eq!(fixture.trace.borrow().len(), if accepted { 5 } else { 3 });
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
    root.remove()?;
    Ok(())
}

#[test]
fn modeled_short_retry_deadline_precedes_readiness_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    let selected = fixed_competing_spec(MODEL_CASE);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(matches!(
        fixture.surface.open(&selected),
        Poll::Ready(Ok(_))
    ));
    let sink = model.sink.borrow().clone().ok_or("missing sink")?;
    sink.event(NativeEvent::BrowserExited { pid: 42 });
    let clock = TickingClock(FakeClock::start());
    let retry_deadline = clock.0.now();
    fixture.deadline = retry_deadline + Duration::from_secs(30);
    let handle = Handle {
        code: Ok(Some(0x535)),
        clock: clock.0.clone(),
        advance: Duration::ZERO,
    };
    let first = ProcessFaultMark::Reached(ProcessFaultState {
        phase: ProcessFaultPhase::PostedEmpty,
        topology: ProcessFaultTopology::SealedSingleViewFrameFree,
        generation: 1,
        reply_state: ControlState::Empty as u32,
        record_count: 1,
        posts: 1,
    });
    fixture.trace.borrow_mut().extend([
        first,
        ProcessFaultMark::Selected(handle.identity()),
        ProcessFaultMark::TerminationCall,
    ]);
    fixture.handle = Some(Box::new(handle));
    assert!(fixture
        .observe_fault_with_clock(ProcessFaultTarget::Browser, first, retry_deadline, &clock)
        .is_err());
    assert!(!fixture.evidence_complete);
    assert_eq!(fixture.trace.borrow().len(), 3);
    let readiness_deadline = fixture.deadline;
    assert!(fixture
        .observe_fault_with_clock(
            ProcessFaultTarget::Browser,
            first,
            readiness_deadline,
            &clock
        )
        .is_ok());
    assert!(fixture.evidence_complete);
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

struct ModeledRendererObservation;

impl ModeledRendererObservation {
    fn new() -> Self {
        crate::Native::reset_process_failure_observations();
        Self
    }
}

impl Drop for ModeledRendererObservation {
    fn drop(&mut self) {
        crate::Native::reset_process_failure_observations();
    }
}

#[test]
fn modeled_early_renderer_observer_enforces_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (boundary, advance, accepted) in [
        (true, Duration::ZERO, false),
        (false, Duration::from_secs(6), false),
        (false, Duration::ZERO, true),
    ] {
        let _observation = ModeledRendererObservation::new();
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        let selected = fixed_competing_spec(MODEL_CASE);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(matches!(
            fixture.surface.open(&selected),
            Poll::Ready(Ok(_))
        ));
        let sink = model.sink.borrow().clone().ok_or("missing sink")?;
        sink.event(NativeEvent::ProcessFailed);
        crate::Native::model_main_renderer_exit();
        let clock = TickingClock(FakeClock::start());
        fixture.deadline = clock.0.now()
            + if boundary {
                Duration::ZERO
            } else {
                Duration::from_secs(5)
            };
        let handle = Handle {
            code: Ok(Some(0x535)),
            clock: clock.0.clone(),
            advance,
        };
        let first = ProcessFaultMark::BeforeRecord {
            generation: 1,
            record_count: 0,
        };
        fixture.trace.borrow_mut().extend([
            first,
            ProcessFaultMark::RendererPresence(crate::RendererPresence::Unique),
            ProcessFaultMark::Selected(handle.identity()),
            ProcessFaultMark::TerminationCall,
        ]);
        fixture.handle = Some(Box::new(handle));
        let result = fixture.observe_early_renderer_with_clock(first, &clock);
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(fixture.evidence_complete, accepted);
        assert_eq!(fixture.trace.borrow().len(), if accepted { 6 } else { 4 });
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        sink.event(NativeEvent::BrowserExited { pid: 42 });
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        drop(sink);
        crate::Native::reset_process_failure_observations();
        let driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        fixture.retire(driver, Err(ERROR), None)?;
        root.remove()?;
    }
    Ok(())
}

#[test]
fn modeled_consuming_control_requires_timely_completed_cas() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (elapsed, accepted) in [
        (Duration::from_millis(999), true),
        (Duration::from_secs(1), false),
        (Duration::from_secs(2), false),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, _model) = fixture(&root)?;
        let clock = FakeClock::start();
        let deadline = clock.now() + Duration::from_secs(1);
        clock.advance(elapsed);
        let state = ProcessFaultState {
            phase: ProcessFaultPhase::PostedReady,
            topology: ProcessFaultTopology::SealedSingleViewFrameFree,
            generation: 1,
            reply_state: ControlState::Ready as u32,
            record_count: 1,
            posts: 1,
        };
        {
            let port = super::ConsumingPort {
                inner: RefCell::new(&mut fixture.surface),
                target: ProcessFaultTarget::Browser,
                inject: false,
                deadline,
                trace: Rc::clone(&fixture.trace),
                state,
                handle: RefCell::new(None),
                failure: RefCell::new(None),
                reached: RefCell::new(false),
            };
            let result = port.on_consuming_with_clock(&clock);
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(*port.reached.borrow(), accepted);
        }
        assert_eq!(fixture.trace.borrow().len(), usize::from(accepted));
        let driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        fixture.retire(driver, Err(ERROR), None)?;
        root.remove()?;
    }
    Ok(())
}

#[test]
fn modeled_pre_record_control_rejects_query_crossing_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (seconds, accepted) in [(0, false), (1, false), (3, true)] {
        crate::Native::reset_process_failure_observations();
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        model.preload_owners.set(true);
        let selected = fixed_competing_spec(MODEL_CASE);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        let Poll::Ready(Ok(browser)) = fixture.surface.open(&selected) else {
            return Err("missing browser".into());
        };
        let record = pos_owner_bridge_codec::CleanupRecordV1::new(
            selected.ceremony_id,
            &selected.folder_name,
            browser.browser_pid,
            browser.creation_filetime,
            browser.image_path_sha256,
        )
        .map_err(|e| e.to_string())?;
        let mut bytes = [0; 4096];
        let size = pos_owner_bridge_codec::encode_cleanup_record(&record, &mut bytes)
            .map_err(|e| e.to_string())?;
        let clock = TickingClock(FakeClock::start());
        let deadline = clock.0.now() + Duration::from_secs(seconds);
        {
            let shared = RefCell::new(&mut fixture.surface);
            let mut store = super::BeforeRecordStore {
                inner: &mut fixture.store,
                surface: &shared,
                inject: false,
                target: ProcessFaultTarget::Browser,
                presence: None,
                deadline,
                trace: Rc::clone(&fixture.trace),
                handle: None,
                failure: None,
                reached: false,
                written: false,
                generation: 1,
                posts: 0,
                ceremony_id: selected.ceremony_id,
            };
            let result = store.on_write_with_clock(&bytes[..size], &clock);
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(store.reached, accepted);
            assert_eq!(fixture.trace.borrow().len(), usize::from(accepted));
        }
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let sink = model.sink.borrow().clone().ok_or("missing sink")?;
        sink.event(NativeEvent::BrowserExited {
            pid: browser.browser_pid,
        });
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        fixture.retire(driver, Err(ERROR), None)?;
        root.remove()?;
    }
    Ok(())
}

#[test]
fn modeled_control_observation_refuses_a_snapshot_after_the_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (mark, presence) in [
        (
            ProcessFaultMark::Navigating {
                generation: 1,
                record_count: 1,
            },
            None,
        ),
        (
            ProcessFaultMark::AwaitingLoad {
                generation: 1,
                record_count: 1,
            },
            None,
        ),
        (
            ProcessFaultMark::Navigating {
                generation: 1,
                record_count: 1,
            },
            Some(crate::RendererPresence::Absent),
        ),
        (
            ProcessFaultMark::AwaitingLoad {
                generation: 1,
                record_count: 1,
            },
            Some(crate::RendererPresence::Absent),
        ),
    ] {
        for (elapsed, accepted) in [
            (Duration::from_millis(999), true),
            (Duration::from_secs(1), false),
            (Duration::from_secs(2), false),
        ] {
            let root = FixtureRoot::new()?;
            let (mut fixture, _model) = fixture(&root)?;
            let clock = FakeClock::start();
            fixture.deadline = clock.now() + Duration::from_secs(1);
            // Model a state/identity or renderer-discovery query completing here.
            clock.advance(elapsed);
            let result = fixture.record_control_observation(mark, presence, &clock);
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(
                fixture.trace.borrow().len(),
                if accepted {
                    1 + usize::from(presence.is_some())
                } else {
                    0
                }
            );
            assert_eq!(
                fixture.early_presence,
                if accepted { presence } else { None }
            );
            assert!(!fixture.evidence_complete);
            let driver =
                readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
            fixture.retire(driver, Err(ERROR), None)?;
            root.remove()?;
        }
    }
    Ok(())
}

#[test]
fn modeled_exit_cutpoint_refuses_unprepared_surface_before_authority() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for inject in [false, true] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        let calls = model.calls.borrow().clone();
        let result = fixture.at_success_exit(inject, Instant::now() + Duration::from_secs(5));
        assert!(result
            .err()
            .is_some_and(|error| error.to_string().starts_with(
                "AwaitingExit retained-object status and matching SDK-event classification failed:"
            )));
        assert_eq!(*model.calls.borrow(), calls);
        assert!(fixture.handle.is_none());
        assert!(fixture.exit_reached.is_none());
        assert!(!fixture.evidence_complete);
        assert!(fixture.trace.borrow().is_empty());
        let (driver, result) = cancelled_driver(&mut fixture)?;
        fixture.retire(driver, result, None)?;
        root.remove()?;
    }
    Ok(())
}

/// Scripted fake Surface state; none of these events is native qualification evidence.
fn modeled_closed_exit_fixture(
    root: &FixtureRoot,
) -> Result<(Fixture, Rc<Factory>, Instant), Box<dyn std::error::Error>> {
    use pos_owner_bridge::{CleanupStore, RequestImage};
    use pos_owner_bridge_codec::{CeremonyKind, CleanupRecordV1, OwnerBridgeControlV1};

    let (mut fixture, model) = fixture(root)?;
    model.navigation_succeeds.set(true);
    let selected = fixed_competing_spec(MODEL_CASE);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    let Poll::Ready(Ok(browser)) = fixture.surface.open(&selected) else {
        return Err("modeled browser unavailable".into());
    };
    assert!(fixture.surface.navigate().is_pending());
    let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
    assert_eq!(
        sink.event(NativeEvent::Navigation {
            uri: crate::NativeText::fixture(crate::OWNER_URL),
            id: 7,
            redirected: false,
        }),
        crate::NativeAction::Allow
    );
    sink.event(NativeEvent::DomLoaded {
        id: 7,
        uri: crate::NativeText::fixture(crate::OWNER_URL),
    });
    assert!(matches!(fixture.surface.navigate(), Poll::Ready(Ok(_))));
    let record = CleanupRecordV1::new(
        selected.ceremony_id,
        &selected.folder_name,
        browser.browser_pid,
        browser.creation_filetime,
        browser.image_path_sha256,
    )
    .map_err(|error| error.to_string())?;
    let mut bytes = [0; 4096];
    let len = pos_owner_bridge_codec::encode_cleanup_record(&record, &mut bytes)
        .map_err(|error| error.to_string())?;
    fixture
        .store
        .write_record(&bytes[..len])
        .map_err(|_| "modeled record")?;
    let request_header =
        OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, selected.ceremony_id, 1)
            .map_err(|error| error.to_string())?
            .encode();
    let reply_header =
        OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, selected.ceremony_id)
            .map_err(|error| error.to_string())?
            .encode();
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes()[..64].copy_from_slice(&request_header);
    fixture
        .surface
        .create_and_write(&request, &reply_header)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture
        .surface
        .zero_close_buffers()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    fixture
        .surface
        .arm_exit_capture(selected.ceremony_id, Rc::clone(&fixture.trace), deadline)
        .map_err(|()| "modeled capture")?;
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok((fixture, model, deadline))
}

#[test]
fn modeled_already_exited_cutpoint_retains_owner_without_termination() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for inject in [false, true] {
        crate::Native::reset_process_failure_observations();
        let root = FixtureRoot::new()?;
        let (mut fixture, model, deadline) = modeled_closed_exit_fixture(&root)?;
        model.set_modeled_exit_code(Some(0));
        let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
        sink.event(NativeEvent::BrowserExited { pid: 42 });
        assert!(fixture.surface.exit_fault_owners_retained());
        fixture.at_success_exit(inject, deadline)?;
        assert!(matches!(
            fixture.exit_reached,
            Some(crate::adapter::surface::ExitBoundary::AlreadyExited(_))
        ));
        assert!(fixture.evidence_complete);
        assert!(fixture.handle.is_some());
        assert!(!model.calls.borrow().contains(&"terminate_exit"));
        assert!(fixture.surface.exit_fault_owners_retained());
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let driver =
            readiness::new_driver(CeremonyId::from_bytes([MODEL_CASE; 16]), Instant::now())?;
        fixture.retire(driver, Err(ERROR), None)?;
        root.remove()?;
    }
    Ok(())
}
