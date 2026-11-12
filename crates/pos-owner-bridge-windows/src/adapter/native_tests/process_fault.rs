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
use crate::adapter::surface::ExitBoundary;
use crate::adapter::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use crate::{
    BufferSlot, NativeFactory, NativeZeroObservation, ProcessFaultHandle, ProcessFaultMark,
    ProcessFaultPhase, ProcessFaultState, ProcessFaultTarget, ProcessFaultTopology,
};

mod model_tests;
mod obstruction;
mod port_tests;
mod quarantined;

#[test]
fn native_quarantined_faults_do_not_release_the_keeper() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let root = FixtureRoot::new()?;
    quarantined::run(Path::new(&runtime), &root.0)?;
    root.remove()
}

type Trace = Rc<RefCell<Vec<ProcessFaultMark>>>;
type CeremonyResult = Result<Verified, BridgeError>;
type DriveResult = Result<CeremonyResult, Box<dyn std::error::Error>>;
type AttemptResult = (CeremonyResult, Option<Box<dyn std::error::Error>>);

// The fixture deadline was set before the test driver's T0. Its origin gives
// a conservative challenge limit; these Get test plans have no enrollment budget.
// Interpret one retained-handle observation without altering the caller's
// identity, clock, trace, or event ordering.
fn require_exit_code(
    result: Result<Option<u32>, ()>,
    query_error: &'static str,
    pending_error: &'static str,
) -> Result<u32, &'static str> {
    result.map_err(|()| query_error)?.ok_or(pending_error)
}

#[test]
fn modeled_retained_exit_code_preserves_each_scenario_error() {
    for (query_error, pending_error) in [
        ("exit query failed", "exit still pending at native event"),
        (
            "recordless exit query failed",
            "recordless process exit pending",
        ),
        (
            "consuming exit query failed",
            "consuming exit still pending",
        ),
        (
            "pre-record exit query failed",
            "pre-record process exit pending",
        ),
        (
            "early renderer exit query failed",
            "early renderer exit pending",
        ),
    ] {
        assert_eq!(
            require_exit_code(Err(()), query_error, pending_error),
            Err(query_error)
        );
        assert_eq!(
            require_exit_code(Ok(None), query_error, pending_error),
            Err(pending_error)
        );
        assert_eq!(
            require_exit_code(Ok(Some(0)), query_error, pending_error),
            Ok(0)
        );
        assert_eq!(
            require_exit_code(Ok(Some(0x535)), query_error, pending_error),
            Ok(0x535)
        );
    }
}

fn interaction_deadline(fixture_deadline: Instant, receipt: Instant) -> Instant {
    use pos_owner_bridge::ceremony::timing::{CHALLENGE_TTL, INTERACTION, READINESS};
    (receipt + INTERACTION).min(fixture_deadline + CHALLENGE_TTL.saturating_sub(READINESS))
}

#[test]
fn interaction_deadline_uses_receipt_and_conservative_challenge_origin() {
    let origin = Instant::now();
    let fixture_deadline = origin + Duration::from_secs(15);
    let receipt = origin + Duration::from_secs(10);
    let interaction = interaction_deadline(fixture_deadline, receipt);
    assert_eq!(interaction, origin + Duration::from_secs(130));
    assert!(origin + Duration::from_secs(129) < interaction);
    assert!(origin + Duration::from_secs(130) >= interaction);
    let late_receipt = origin + Duration::from_secs(40);
    let challenge = interaction_deadline(fixture_deadline, late_receipt);
    assert_eq!(challenge, origin + Duration::from_secs(150));
    assert!(origin + Duration::from_secs(149) < challenge);
    assert!(origin + Duration::from_secs(150) >= challenge);
}

fn validate_process_failures(
    observed: &[crate::NativeProcessFailure],
    expected: Option<ProcessFaultTarget>,
) -> TestResult {
    use crate::NativeProcessFailure::{BrowserExited, MainRendererExited};
    let matches = match expected {
        None => observed.is_empty(),
        Some(ProcessFaultTarget::Renderer) => observed == [MainRendererExited],
        Some(ProcessFaultTarget::Browser) => observed.is_empty() || observed == [BrowserExited],
    };
    if matches {
        Ok(())
    } else {
        Err("unexpected or unclassified native process failure during complete case".into())
    }
}

fn check_final_process_failures(expected: Option<ProcessFaultTarget>) -> TestResult {
    let observed = crate::Native::classified_process_failure_observations();
    validate_process_failures(&observed, expected)
}

#[test]
fn final_failure_evidence_rejects_late_and_unclassified_events() {
    use crate::NativeProcessFailure::{BrowserExited, MainRendererExited, Other, Unavailable};
    assert!(validate_process_failures(&[], None).is_ok());
    assert!(
        validate_process_failures(&[MainRendererExited], Some(ProcessFaultTarget::Renderer))
            .is_ok()
    );
    assert!(validate_process_failures(&[], Some(ProcessFaultTarget::Browser)).is_ok());
    assert!(validate_process_failures(&[BrowserExited], Some(ProcessFaultTarget::Browser)).is_ok());
    for expected in [
        None,
        Some(ProcessFaultTarget::Renderer),
        Some(ProcessFaultTarget::Browser),
    ] {
        for late in [Other, Unavailable, BrowserExited, MainRendererExited] {
            assert!(validate_process_failures(&[MainRendererExited, late], expected).is_err());
            assert!(validate_process_failures(&[BrowserExited, late], expected).is_err());
        }
        assert!(validate_process_failures(&[Other], expected).is_err());
        assert!(validate_process_failures(&[Unavailable], expected).is_err());
    }
    assert!(validate_process_failures(&[BrowserExited], None).is_err());
    assert!(validate_process_failures(&[MainRendererExited], None).is_err());
    assert!(validate_process_failures(&[], Some(ProcessFaultTarget::Renderer)).is_err());
    assert!(
        validate_process_failures(&[BrowserExited], Some(ProcessFaultTarget::Renderer)).is_err()
    );
    assert!(
        validate_process_failures(&[MainRendererExited], Some(ProcessFaultTarget::Browser))
            .is_err()
    );
    assert_eq!(
        validate_process_failures(&[Other], None)
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("unexpected or unclassified native process failure during complete case")
    );
}

fn fixed_competing_spec(byte: u8) -> SurfaceSpec {
    let ceremony_id = CeremonyId::from_bytes([byte; 16]);
    SurfaceSpec {
        ceremony_id,
        folder_name: pos_owner_bridge::folder_name(&ceremony_id),
        owner_window: None,
    }
}

fn competing_spec() -> SurfaceSpec {
    fixed_competing_spec(0x7f)
}

fn pre_environment_competing_spec() -> SurfaceSpec {
    fixed_competing_spec(0x7c)
}

#[test]
fn pre_environment_competitor_is_distinct_from_each_declared_case() {
    let competitor = pre_environment_competing_spec();
    for number in [0x7e, 0x7f, 0x80, 0x81] {
        assert_ne!(competitor.ceremony_id, CeremonyId::from_bytes([number; 16]));
    }
    assert_eq!(
        competitor.folder_name,
        pos_owner_bridge::folder_name(&competitor.ceremony_id)
    );
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

type TargetFaultCase<'a> = dyn FnMut(
        &Path,
        &Path,
        u8,
        ProcessFaultTarget,
        bool,
    ) -> Result<ProcessFaultState, Box<dyn std::error::Error>>
    + 'a;

fn run_target_pair(
    runtime: &Path,
    root: &Path,
    number: u8,
    target: ProcessFaultTarget,
    case: &mut TargetFaultCase<'_>,
    mismatch: &str,
) -> TestResult {
    let control = case(runtime, root, number, target, false)?;
    let fault = case(runtime, root, number + 1, target, true)?;
    assert_eq!(control, fault, "{mismatch}");
    Ok(())
}

#[test]
fn modeled_target_pair_preserves_order_and_short_circuits_errors() {
    let state = ProcessFaultState {
        phase: ProcessFaultPhase::PostedReceipt,
        topology: ProcessFaultTopology::SealedSingleViewFrameFree,
        generation: 1,
        reply_state: ControlState::Received as u32,
        record_count: 1,
        posts: 1,
    };
    for fail_at in [Some(false), Some(true), None] {
        let mut calls = Vec::new();
        let mut case =
            |_: &Path, _: &Path, number: u8, target: ProcessFaultTarget, inject: bool| {
                calls.push((number, target, inject));
                if fail_at == Some(inject) {
                    return Err(if inject {
                        "fault failed"
                    } else {
                        "control failed"
                    }
                    .into());
                }
                Ok(state)
            };
        let result = run_target_pairs(
            Path::new("."),
            Path::new("."),
            &[
                (0x31, ProcessFaultTarget::Browser),
                (0x33, ProcessFaultTarget::Renderer),
            ],
            &mut case,
            "modeled mismatch",
        );
        let expected = fail_at.map(|inject| {
            if inject {
                "fault failed"
            } else {
                "control failed"
            }
        });
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            expected
        );
        let mut expected_calls = vec![(0x31, ProcessFaultTarget::Browser, false)];
        if fail_at != Some(false) {
            expected_calls.push((0x32, ProcessFaultTarget::Browser, true));
        }
        if fail_at.is_none() {
            expected_calls.extend([
                (0x33, ProcessFaultTarget::Renderer, false),
                (0x34, ProcessFaultTarget::Renderer, true),
            ]);
        }
        assert_eq!(calls, expected_calls);
    }
}

#[test]
fn modeled_target_pair_preserves_mismatch_panic() -> TestResult {
    let state = ProcessFaultState {
        phase: ProcessFaultPhase::PostedReceipt,
        topology: ProcessFaultTopology::SealedSingleViewFrameFree,
        generation: 1,
        reply_state: ControlState::Received as u32,
        record_count: 1,
        posts: 1,
    };
    let mut case = |_: &Path, _: &Path, _: u8, _: ProcessFaultTarget, inject: bool| {
        let mut observed = state;
        if inject {
            observed.posts = 2;
        }
        Ok(observed)
    };
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _result = run_target_pair(
            Path::new("."),
            Path::new("."),
            0x31,
            ProcessFaultTarget::Browser,
            &mut case,
            "modeled mismatch",
        );
    }))
    .err()
    .ok_or("different states must panic")?;
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied());
    assert!(message.is_some_and(|text| text.contains("modeled mismatch")));
    Ok(())
}

fn run_target_pairs(
    runtime: &Path,
    root: &Path,
    cases: &[(u8, ProcessFaultTarget)],
    case: &mut TargetFaultCase<'_>,
    mismatch: &str,
) -> TestResult {
    for &(number, target) in cases {
        run_target_pair(runtime, root, number, target, case, mismatch)?;
    }
    Ok(())
}

fn run() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_target_pairs(
        Path::new(&runtime),
        &root.0,
        &[
            (0x31, ProcessFaultTarget::Renderer),
            (0x33, ProcessFaultTarget::Browser),
        ],
        &mut run_case,
        "control and fault reached different substates",
    )?;
    run_recordless_case(Path::new(&runtime), &root.0, 0x35, false)?;
    run_recordless_case(Path::new(&runtime), &root.0, 0x36, true)?;
    run_target_pairs(
        Path::new(&runtime),
        &root.0,
        &[
            (0x37, ProcessFaultTarget::Renderer),
            (0x39, ProcessFaultTarget::Browser),
        ],
        &mut run_success_releasing,
        "release control and fault reached different states",
    )?;
    let control = run_success_exit(Path::new(&runtime), &root.0, 0x3b, false)?;
    let fault = run_success_exit(Path::new(&runtime), &root.0, 0x3c, true)?;
    let state = |boundary| match boundary {
        ExitBoundary::ActiveStatus(state)
        | ExitBoundary::ObjectExitedAwaitingSdk(state)
        | ExitBoundary::AlreadyExited(state) => state,
    };
    assert_eq!(
        state(control),
        state(fault),
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
    run_target_pairs(
        Path::new(&runtime),
        &root.0,
        &[
            (0x41, ProcessFaultTarget::Renderer),
            (0x43, ProcessFaultTarget::Browser),
        ],
        &mut run_posted_empty,
        "empty-reply control and fault reached different states",
    )?;
    let control = run_first_opening_browser(Path::new(&runtime), &root.0, 0x45, false)?;
    let fault = run_first_opening_browser(Path::new(&runtime), &root.0, 0x46, true)?;
    assert_eq!(
        control, fault,
        "opening control and fault reached different cutpoints"
    );
    run_target_pairs(
        Path::new(&runtime),
        &root.0,
        &[
            (0x4b, ProcessFaultTarget::Renderer),
            (0x4d, ProcessFaultTarget::Browser),
        ],
        &mut run_posted_writing,
        "writing control and fault reached different states",
    )?;
    run_target_pairs(
        Path::new(&runtime),
        &root.0,
        &[
            (0x70, ProcessFaultTarget::Renderer),
            (0x72, ProcessFaultTarget::Browser),
        ],
        &mut run_posted_ready,
        "ready control and fault reached different states",
    )?;
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
    exit_reached: Option<ExitBoundary>,
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
    fn new_obstructed(
        runtime_path: &Path,
        root: &Path,
        number: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = root.join("environment-obstruction");
        crate::create_private_directory(&root)?;
        let runtime = Arc::new(crate::verify_fixed_runtime(runtime_path, &root)?);
        let id = CeremonyId::from_bytes([number; 16]);
        let expected = root.join(pos_owner_bridge::folder_name(&id));
        let factory: Rc<dyn NativeFactory> = Rc::new(obstruction::ObstructionFactory::new(
            crate::Native::owner_factory()?,
            expected,
        ));
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
            number,
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
        })
    }

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
            if let (None, Step::Pending, Some(receipt)) =
                (self.reached, &step, driver.first_receipt_at())
            {
                self.at_fault_point(driver, target, inject, receipt)?;
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
        receipt: Instant,
    ) -> TestResult {
        let deadline = interaction_deadline(self.deadline, receipt);
        let state = self
            .surface
            .posted_fault_state(driver.posts())
            .map_err(|()| "unverified pre-fault state")?;
        if ControlState::try_from(state.reply_state).ok() != Some(ControlState::Received) {
            return Err("the page was not in RECEIVED".into());
        }
        if Instant::now() >= deadline {
            return Err("posted receipt fault point expired".into());
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
                    .inject_posted_fault(target, seal)
                    .map_err(|()| "owned process fault refused")?,
            );
            self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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

    fn pre_environment_competitor_blocked(
        &mut self,
        ceremony: &CeremonyId,
        expected: crate::adapter::surface::PreEnvironmentRetention,
    ) -> bool {
        let competitor = pre_environment_competing_spec();
        if &competitor.ceremony_id == ceremony {
            return false;
        }
        if self.surface.pre_environment_retention(ceremony) != Some(expected) {
            return false;
        }
        let rejected = matches!(self.surface.open(&competitor), Poll::Ready(Err(_)));
        let after = self.surface.pre_environment_retention(ceremony);
        rejected && after == Some(expected)
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
        self.observe_fault_until(target, first, self.deadline)
    }

    fn observe_fault_until(
        &mut self,
        target: ProcessFaultTarget,
        first: ProcessFaultMark,
        deadline: Instant,
    ) -> TestResult {
        self.observe_fault_with_clock(target, first, deadline, &SystemClock)
    }

    fn observe_fault_with_clock(
        &mut self,
        target: ProcessFaultTarget,
        first: ProcessFaultMark,
        deadline: Instant,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        // Progress the owning STA until its actual event; never wait on a process
        // handle or infer an exit from a PID. Query the retained handle once when
        // that event arrives; an indeterminate result fails this case.
        loop {
            if clock.now() >= deadline {
                return Err("native fault event timed out".into());
            }
            if let Some(event) = self
                .surface
                .posted_fault_event(target)
                .map_err(|()| "unexpected native fault event")?
            {
                if matches!(first, ProcessFaultMark::ReachedExit(_))
                    && !self.surface.matching_exit_event()
                {
                    return Err("exit event was not the unique matching callback".into());
                }
                let held = self.handle.as_ref().ok_or("fault handle disappeared")?;
                let identity = held.identity();
                let code = require_exit_code(
                    held.exit_code(),
                    "exit query failed",
                    "exit still pending at native event",
                )?;
                if clock.now() >= deadline {
                    return Err("native fault event timed out".into());
                }
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
            readiness::pump(&self.surface)?;
        }
    }

    fn retire(
        mut self,
        driver: CeremonyDriver,
        result: Result<Verified, BridgeError>,
        restart_orphans: Option<CeremonyId>,
    ) -> TestResult {
        let mut progress = super::trace::Trace::new(u64::from(self.number), Instant::now());
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=enter",
            self.number
        );
        retirement::retire(
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
            driver,
            result,
            |surface, driver, loopback| progress.update("retirement", surface, driver, loopback),
        );
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=retired",
            self.number
        );
        // Retain the process object and its creating STA through actual retirement.
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=handle-drop-enter",
            self.number
        );
        drop(self.handle.take());
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=handle-drop-return surface-drop-enter",
            self.number
        );
        drop(self.surface);
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=surface-drop-return",
            self.number
        );
        assert!(self.store.records()?.is_empty());
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=factory-stop-enter",
            self.number
        );
        Rc::get_mut(&mut self.factory)
            .ok_or("fault factory still shared")?
            .stop()?;
        let _logged = writeln!(
            std::io::stderr(),
            "NATIVE_FAULT_RETIRE case={} stage=factory-stop-return",
            self.number
        );
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

#[test]
fn native_interaction_cutpoints_outlive_fixture_readiness_ceiling() -> TestResult {
    type Drive = fn(&mut Fixture, &mut CeremonyDriver, ProcessFaultTarget, bool) -> DriveResult;
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let root = FixtureRoot::new()?;
    let cases: [(u8, FixtureProfile, Drive, bool); 4] = [
        (0xe2, FixtureProfile::Pending, Fixture::drive, true),
        (
            0xe3,
            FixtureProfile::SuccessfulGetWritingDelay,
            Fixture::drive_posted_writing,
            false,
        ),
        (
            0xe4,
            FixtureProfile::SuccessfulGetReleaseDelay,
            Fixture::drive_posted_ready,
            false,
        ),
        (
            0xe5,
            FixtureProfile::SuccessfulGetReleaseDelay,
            Fixture::drive_consuming,
            false,
        ),
    ];
    let mut failures = Vec::new();
    for (number, profile, drive, inject) in cases {
        crate::Native::reset_process_failure_observations();
        let mut fixture = Fixture::new(Path::new(&runtime), &root.0, number, profile)?;
        // Keep the Surface's readiness bound intact while expiring the
        // unrelated fixture ceiling for this cutpoint-only regression.
        fixture.deadline = Instant::now();
        let _zero_witness = ZeroWitness::arm();
        let mut driver =
            readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            drive(
                &mut fixture,
                &mut driver,
                ProcessFaultTarget::Renderer,
                inject,
            )
        }));
        let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
        let observed = driver.first_receipt_at().is_some()
            && fixture.reached.is_some()
            && fixture.evidence_complete;
        fixture.retire(driver, result, None)?;
        if let Some(error) = failure {
            failures.push(format!("case {number}: {error}"));
        } else if !observed {
            failures.push(format!("case {number}: interaction evidence missing"));
        }
    }
    root.remove()?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
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
            if !inject
                && reached_opening
                && !cancelled
                && driver.first_receipt_at().is_some_and(|receipt| {
                    receipt < driver.t0() + pos_owner_bridge::ceremony::timing::READINESS
                })
            {
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
        self.observe_recordless_with_clock(browser, &SystemClock)
    }

    fn observe_recordless_with_clock(
        &mut self,
        browser: pos_owner_bridge::ProcessIdentity,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        loop {
            if clock.now() >= self.deadline {
                return Err("recordless browser exit timed out".into());
            }
            if let Some(event) = self
                .surface
                .recordless_fault_event()
                .map_err(|()| "mismatched recordless browser exit")?
            {
                let held = self
                    .handle
                    .as_ref()
                    .ok_or("recordless handle disappeared")?;
                let code = require_exit_code(
                    held.exit_code(),
                    "recordless exit query failed",
                    "recordless process exit pending",
                )?;
                if clock.now() >= self.deadline {
                    return Err("recordless browser exit timed out".into());
                }
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
            readiness::pump(&self.surface)?;
        }
    }
}

/// Verdict over observations captured before ordinary recordless retirement.
struct RecordlessVerdict<'a> {
    inject: bool,
    evidence_complete: bool,
    result_error: Option<BridgeError>,
    slot_wiped: bool,
    plan_wiped_if_quarantined: bool,
    failures: &'a [Option<bool>],
}

impl RecordlessVerdict<'_> {
    fn validate(&self) -> TestResult {
        if !self.evidence_complete || self.result_error.is_none() {
            return Err("recordless evidence incomplete".into());
        }
        if !self.slot_wiped || !self.plan_wiped_if_quarantined {
            return Err(
                "recordless ceremony secrets were not wiped at their required boundary".into(),
            );
        }
        if !self.inject && !self.failures.is_empty() {
            return Err("recordless no-fault control observed a process failure".into());
        }
        Ok(())
    }
}

#[test]
fn modeled_recordless_verdict_requires_evidence_wipe_and_control_absence() {
    let error = BridgeError::Lifecycle(pos_owner_bridge::LifecycleCode::ReadinessTimeout);
    let mut evidence = RecordlessVerdict {
        inject: false,
        evidence_complete: true,
        result_error: Some(error),
        slot_wiped: true,
        plan_wiped_if_quarantined: true,
        failures: &[],
    };
    assert!(evidence.validate().is_ok());
    evidence.evidence_complete = false;
    assert_eq!(
        evidence.validate().err().map(|e| e.to_string()).as_deref(),
        Some("recordless evidence incomplete")
    );
    evidence.evidence_complete = true;
    evidence.result_error = None;
    assert!(evidence.validate().is_err());
    evidence.result_error = Some(error);
    evidence.slot_wiped = false;
    assert!(evidence.validate().is_err());
    evidence.slot_wiped = true;
    evidence.plan_wiped_if_quarantined = false;
    assert!(evidence.validate().is_err());
    evidence.plan_wiped_if_quarantined = true;
    evidence.failures = &[Some(true)];
    assert_eq!(
        evidence.validate().err().map(|e| e.to_string()).as_deref(),
        Some("recordless no-fault control observed a process failure")
    );
    evidence.inject = true;
    assert!(evidence.validate().is_ok());
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
    RecordlessVerdict {
        inject,
        evidence_complete,
        result_error,
        slot_wiped,
        plan_wiped_if_quarantined,
        failures: &failures,
    }
    .validate()
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
                let deadline = step_started + pos_owner_bridge::ceremony::timing::RELEASE_WINDOW;
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
            self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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

#[derive(Clone, Copy)]
enum ReleaseMode {
    Standard,
    BrowserFault,
}

struct ReleaseVerdict {
    mode: ReleaseMode,
    error: Option<BridgeError>,
    verified: bool,
    complete: bool,
    blocked: bool,
    wipe: WipeObservation,
    close: Option<crate::adapter::surface::CloseObservation>,
}

impl ReleaseVerdict {
    fn validate(&self) -> TestResult {
        let valid = self.complete
            && self.wipe.native
            && ((self.verified && self.error.is_none())
                || (matches!(self.mode, ReleaseMode::BrowserFault)
                    && self.error
                        == Some(BridgeError::Quarantine(
                            pos_owner_bridge::QuarantineCode::ControllerCloseFailed,
                        ))
                    && self.wipe.request_and_prf
                    && self.wipe.plan_if_quarantined
                    && self.blocked
                    && self.close.is_some_and(|close| {
                        close.removed
                            == Err(crate::NativeError {
                                operation: crate::Operation::Subscription,
                                failure: crate::Failure::CallFailed,
                            })
                            && close.closed.is_ok()
                            && close.buffers_closed
                            && !close.buffers_uncertain
                            && close.had_controller
                    })));
        if valid {
            Ok(())
        } else {
            Err("successful release or nonzero native reply wipe was not established".into())
        }
    }
}

#[test]
fn release_verdict_requires_the_exact_observed_quarantine_evidence() {
    use crate::adapter::surface::CloseObservation;
    let close = CloseObservation {
        removed: Err(crate::NativeError {
            operation: crate::Operation::Subscription,
            failure: crate::Failure::CallFailed,
        }),
        closed: Ok(()),
        buffers_closed: true,
        buffers_uncertain: false,
        had_controller: true,
    };
    let mut verdict = ReleaseVerdict {
        mode: ReleaseMode::BrowserFault,
        error: Some(BridgeError::Quarantine(
            pos_owner_bridge::QuarantineCode::ControllerCloseFailed,
        )),
        verified: false,
        complete: true,
        blocked: true,
        wipe: WipeObservation {
            request_and_prf: true,
            plan_if_quarantined: true,
            native: true,
        },
        close: Some(close),
    };
    assert!(verdict.validate().is_ok());
    verdict.mode = ReleaseMode::Standard;
    assert!(verdict.validate().is_err());
    verdict.mode = ReleaseMode::BrowserFault;
    verdict.close = None;
    assert!(verdict.validate().is_err());
    verdict.close = Some(CloseObservation {
        closed: Err(crate::NativeError {
            operation: crate::Operation::Controller,
            failure: crate::Failure::CallFailed,
        }),
        ..close
    });
    assert!(verdict.validate().is_err());
    verdict.close = Some(CloseObservation {
        removed: Ok(()),
        ..close
    });
    assert!(verdict.validate().is_err());
    verdict.close = Some(CloseObservation {
        buffers_uncertain: true,
        ..close
    });
    assert!(verdict.validate().is_err());
    verdict.close = Some(CloseObservation {
        buffers_closed: false,
        ..close
    });
    assert!(verdict.validate().is_err());
    verdict.close = Some(CloseObservation {
        had_controller: false,
        ..close
    });
    assert!(verdict.validate().is_err());
    verdict.close = Some(close);
    verdict.complete = false;
    assert!(verdict.validate().is_err());
    verdict.complete = true;
    verdict.wipe.request_and_prf = false;
    assert!(verdict.validate().is_err());
    verdict.wipe.request_and_prf = true;
    verdict.wipe.plan_if_quarantined = false;
    assert!(verdict.validate().is_err());
    verdict.wipe.plan_if_quarantined = true;
    verdict.wipe.native = false;
    assert!(verdict.validate().is_err());
    verdict.wipe.native = true;
    verdict.blocked = false;
    assert!(verdict.validate().is_err());
    verdict.blocked = true;
    verdict.error = Some(BridgeError::Quarantine(
        pos_owner_bridge::QuarantineCode::CleanupTimeout,
    ));
    assert!(verdict.validate().is_err());
}

#[test]
fn release_verdict_requires_complete_verified_success_and_native_zeroing() {
    let mut verdict = ReleaseVerdict {
        mode: ReleaseMode::Standard,
        error: None,
        verified: true,
        complete: true,
        blocked: false,
        wipe: WipeObservation {
            request_and_prf: false,
            plan_if_quarantined: false,
            native: true,
        },
        close: None,
    };
    assert!(verdict.validate().is_ok());
    verdict.complete = false;
    assert!(verdict.validate().is_err());
    verdict.complete = true;
    verdict.wipe.native = false;
    assert!(verdict.validate().is_err());
    verdict.wipe.native = true;
    verdict.verified = false;
    assert!(verdict.validate().is_err());
    verdict.verified = true;
    verdict.error = Some(BridgeError::Quarantine(
        pos_owner_bridge::QuarantineCode::CleanupTimeout,
    ));
    assert_eq!(
        verdict
            .validate()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("successful release or nonzero native reply wipe was not established")
    );
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
    let error = result.as_ref().err().copied();
    let blocked = if error.is_some() {
        fixture.handle.is_some()
            && fixture.surface.release_quarantine_owners_retained()
            && matches!(fixture.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            && fixture.surface.release_quarantine_owners_retained()
    } else {
        true
    };
    let verdict = ReleaseVerdict {
        mode: if inject && target == ProcessFaultTarget::Browser {
            ReleaseMode::BrowserFault
        } else {
            ReleaseMode::Standard
        },
        error,
        verified,
        complete,
        blocked,
        wipe: WipeObservation {
            request_and_prf: driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0),
            plan_if_quarantined: driver.plan_secrets_clear(),
            native: native_zeroed,
        },
        close: fixture.surface.initial_close_observation(),
    };
    let _logged = writeln!(std::io::stderr(), "NATIVE_RELEASE_VERDICT case={number} error={error:?} verified={verified} complete={complete} blocked={blocked} wiped={} plan_wiped={} native_zeroed={native_zeroed} close={:?}", verdict.wipe.request_and_prf, verdict.wipe.plan_if_quarantined, verdict.close);
    fixture.retire(driver, result, None)?;
    check_final_process_failures(inject.then_some(target))?;
    if let Some(error) = failure {
        return Err(error);
    }
    verdict.validate()?;
    reached.ok_or_else(|| "successful release point was not reached".into())
}

#[test]
fn native_release_cutpoint_uses_release_window_after_fixture_readiness_ceiling() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let root = FixtureRoot::new()?;
    crate::Native::reset_process_failure_observations();
    let number = 0xe0;
    let mut fixture = Fixture::new(
        Path::new(&runtime),
        &root.0,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    // Surface retains its original readiness deadline. Only the unrelated
    // fixture-wide ceiling is expired to exercise a later release cutpoint.
    fixture.deadline = Instant::now();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_success_releasing(&mut driver, ProcessFaultTarget::Browser, false)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let reached = fixture.reached;
    let complete = fixture.evidence_complete;
    let verified = result.is_ok() && has_synthetic_success_prf(&driver);
    fixture.retire(driver, result, None)?;
    root.remove()?;
    if let Some(error) = failure {
        return Err(error);
    }
    assert!(verified && complete);
    assert!(reached.is_some());
    Ok(())
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
            let deadline = step_started + pos_owner_bridge::ceremony::timing::EXIT_WINDOW;
            if self.exit_reached.is_none() && has_synthetic_success_prf(driver) {
                self.surface
                    .arm_exit_capture(
                        CeremonyId::from_bytes([self.number; 16]),
                        Rc::clone(&self.trace),
                        deadline,
                    )
                    .map_err(|()| "exit capture could not be armed")?;
            }
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
        let boundary = self
            .surface
            .classify_exit_boundary(deadline)
            .map_err(|()| {
                format!(
                    "AwaitingExit retained-object status and matching SDK-event classification failed: {}",
                    self.surface.fixture_progress()
                )
            })?;
        let cutpoint_remaining = deadline.saturating_duration_since(Instant::now());
        if Instant::now() >= deadline {
            return Err("successful exit fault point expired".into());
        }
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "NATIVE_EXIT_CUTPOINT_OBSERVED case={} boundary={boundary:?} active_status=259_ambiguous_not_liveness remaining_ms={}",
            self.number,
            cutpoint_remaining.as_millis(),
        );
        self.exit_reached = Some(boundary);
        if !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            || !self.surface.exit_fault_owners_retained()
        {
            return Err("a competing exit-phase Surface opening was not blocked".into());
        }
        match boundary {
            ExitBoundary::ActiveStatus(state) => {
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::ReachedExit(state));
                if inject {
                    self.handle = Some(
                        self.surface
                            .consume_exit_capture(deadline, true)
                            .map_err(|()| "successful exit fault refused")?,
                    );
                    self.observe_fault_until(
                        ProcessFaultTarget::Browser,
                        ProcessFaultMark::ReachedExit(state),
                        deadline,
                    )?;
                } else {
                    self.handle = Some(
                        self.surface
                            .consume_exit_capture(deadline, false)
                            .map_err(|()| "exit control capture refused")?,
                    );
                    self.observe_exit_control(deadline)?;
                }
            }
            ExitBoundary::ObjectExitedAwaitingSdk(_) | ExitBoundary::AlreadyExited(_) => {
                self.handle = Some(
                    self.surface
                        .consume_exit_capture(deadline, false)
                        .map_err(|()| "exited object capture refused")?,
                );
                self.observe_exit_control(deadline)?;
            }
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
            "NATIVE_SUCCESS_EXIT case={} boundary={boundary:?} active_status=259_ambiguous_not_liveness requested_injection={inject} actual_injection={} cutpoint_remaining_ms={} final_remaining_ms={} trace={:?}",
            self.number,
            inject && matches!(boundary, ExitBoundary::ActiveStatus(_)),
            cutpoint_remaining.as_millis(),
            deadline.saturating_duration_since(Instant::now()).as_millis(),
            self.trace.borrow()
        )?;
        Ok(())
    }

    fn observe_exit_control(&mut self, deadline: Instant) -> TestResult {
        loop {
            if Instant::now() >= deadline {
                return Err("control exit timed out".into());
            }
            if self
                .surface
                .posted_fault_event(ProcessFaultTarget::Browser)
                .map_err(|()| "control exit mismatched")?
                .is_some()
            {
                if !self.surface.matching_exit_event() {
                    return Err("control exit was not the unique matching callback".into());
                }
                let handle = self.handle.as_ref().ok_or("control handle missing")?;
                if handle
                    .exit_code()
                    .map_err(|()| "control exit query failed")?
                    != Some(0)
                {
                    return Err("control exit code was not zero".into());
                }
                if Instant::now() >= deadline {
                    return Err("control exit timed out".into());
                }
                self.trace.borrow_mut().extend([
                    ProcessFaultMark::OwnBrowserExited,
                    ProcessFaultMark::ExitCode(0),
                ]);
                self.evidence_complete = true;
                return Ok(());
            }
            readiness::pump(&self.surface)?;
        }
    }
}

fn run_success_exit(
    runtime: &Path,
    root: &Path,
    number: u8,
    inject: bool,
) -> Result<ExitBoundary, Box<dyn std::error::Error>> {
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
    let actual_fault =
        inject && reached.is_some_and(|state| matches!(state, ExitBoundary::ActiveStatus(_)));
    check_final_process_failures(actual_fault.then_some(ProcessFaultTarget::Browser))?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !verified || !complete || !native_zeroed {
        return Err("successful exit or nonzero native reply wipe was not established".into());
    }
    reached.ok_or_else(|| "successful exit point was not reached".into())
}

#[test]
fn native_exit_cutpoint_uses_exit_window_after_fixture_readiness_ceiling() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let root = FixtureRoot::new()?;
    crate::Native::reset_process_failure_observations();
    let number = 0xe1;
    let mut fixture = Fixture::new(
        Path::new(&runtime),
        &root.0,
        number,
        FixtureProfile::SuccessfulGetReleaseDelay,
    )?;
    // Preserve the Surface's original readiness deadline; expire only the
    // unrelated fixture-wide ceiling before the later exit cutpoint.
    fixture.deadline = Instant::now();
    let _zero_witness = ZeroWitness::arm();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_success_exit(&mut driver, false)
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let reached = fixture.exit_reached;
    let complete = fixture.evidence_complete;
    let verified = result.is_ok() && has_synthetic_success_prf(&driver) && driver.request_clear();
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations)
        && observations
            .get(1)
            .is_some_and(|reply| reply.before_nonzero == Some(true));
    fixture.retire(driver, result, None)?;
    root.remove()?;
    if let Some(error) = failure {
        return Err(error);
    }
    assert!(verified && complete && native_zeroed);
    assert!(reached.is_some());
    Ok(())
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
    fn record_control_observation(
        &mut self,
        mark: ProcessFaultMark,
        presence: Option<crate::RendererPresence>,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        if clock.now() >= self.deadline {
            return Err("control observation expired".into());
        }
        self.trace.borrow_mut().push(mark);
        if let Some(presence) = presence {
            self.early_presence = Some(presence);
            self.trace
                .borrow_mut()
                .push(ProcessFaultMark::RendererPresence(presence));
        }
        Ok(())
    }

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
                self.record_control_observation(mark, None, &SystemClock)?;
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
                self.record_control_observation(mark, None, &SystemClock)?;
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
                    self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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
    fn opening_first_browser(
        &mut self,
    ) -> Result<(pos_owner_bridge::ProcessIdentity, ProcessFaultMark), Box<dyn std::error::Error>>
    {
        loop {
            if !self.surface.recordless_opening_ready() || Instant::now() >= self.deadline {
                return Err("opening browser cutpoint was not reached".into());
            }
            match self.surface.pending_opening_completion() {
                None => {
                    if let Some(browser) = self
                        .surface
                        .prepare_pending_opening_browser()
                        .map_err(|()| "pending-opening browser or callback indeterminate")?
                    {
                        return Ok((
                            browser,
                            ProcessFaultMark::PendingOpening {
                                generation: 1,
                                record_count: 0,
                            },
                        ));
                    }
                    readiness::pump(&self.surface)?;
                }
                Some(true) => {
                    if !controller_held_before_exit(&crate::Native::callback_order()) {
                        return Err("held controller callback order was not established".into());
                    }
                    let browser = self
                        .surface
                        .prepare_recordless_browser()
                        .map_err(|()| "held-opening browser identity indeterminate")?;
                    return Ok((
                        browser,
                        ProcessFaultMark::RecordlessOpening {
                            generation: 1,
                            record_count: 0,
                        },
                    ));
                }
                Some(false) => {
                    return Err("controller callback failed before browser cutpoint".into())
                }
            }
        }
    }

    fn opening_first_owners_retained(&mut self, mark: ProcessFaultMark) -> bool {
        match mark {
            ProcessFaultMark::PendingOpening { .. } => {
                self.surface.pending_opening_owners_retained()
                    && self.surface.pending_opening_completion().is_none()
            }
            ProcessFaultMark::RecordlessOpening { .. } => {
                self.surface.recordless_fault_owners_retained()
                    && self.surface.pending_opening_completion() == Some(true)
            }
            _ => false,
        }
    }

    fn inject_opening_first_browser(
        &mut self,
        browser: pos_owner_bridge::ProcessIdentity,
        mark: ProcessFaultMark,
    ) -> TestResult {
        let seal = crate::FaultSeal {
            trace: Rc::clone(&self.trace),
            deadline: self.deadline,
        };
        match mark {
            ProcessFaultMark::PendingOpening { .. } => {
                self.handle = Some(
                    self.surface
                        .inject_pending_opening_browser(seal)
                        .map_err(|()| "pending-opening browser fault refused")?,
                );
                self.observe_pending_opening(browser, mark)?;
                if !self.surface.pending_opening_owners_retained() {
                    return Err("pending-opening callback owner not retained".into());
                }
            }
            ProcessFaultMark::RecordlessOpening { .. } => {
                self.handle = Some(
                    self.surface
                        .inject_recordless_browser(seal)
                        .map_err(|()| "held-opening browser fault refused")?,
                );
                self.observe_recordless(browser)?;
                if !self.surface.recordless_fault_owners_retained() {
                    return Err("held-opening callback owner not retained".into());
                }
            }
            _ => return Err("unexpected opening fault cutpoint".into()),
        }
        Ok(())
    }

    fn drive_first_opening_browser(
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
                if driver.generation() != 1 || driver.posts() != 0 {
                    return Err("opening generation or post count changed".into());
                }
                let (browser, first) = self.opening_first_browser()?;
                self.trace.borrow_mut().push(first);
                if !self.opening_first_owners_retained(first)
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || !self.opening_first_owners_retained(first)
                {
                    return Err("opening owners or blocked admission missing".into());
                }
                let _logged = writeln!(
                    std::io::stderr(),
                    "NATIVE_OPENING_FIRST case={} inject={inject} cutpoint={first:?}",
                    self.number
                );
                reached = true;
                if inject {
                    self.inject_opening_first_browser(browser, first)?;
                    self.surface.controller_lost();
                    cancelled = true;
                }
            }
            if !inject
                && reached
                && !cancelled
                && driver.first_receipt_at().is_some_and(|receipt| {
                    receipt < driver.t0() + pos_owner_bridge::ceremony::timing::READINESS
                })
            {
                self.evidence_complete = true;
                self.surface.controller_lost();
                cancelled = true;
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => return Err("opening driver ended without result".into()),
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }

    fn observe_pending_opening(
        &mut self,
        browser: pos_owner_bridge::ProcessIdentity,
        first: ProcessFaultMark,
    ) -> TestResult {
        self.observe_pending_opening_with_observations(
            browser,
            first,
            &SystemClock,
            Box::new(crate::Native::callback_order),
        )
    }

    fn observe_pending_opening_with_observations(
        &mut self,
        browser: pos_owner_bridge::ProcessIdentity,
        first: ProcessFaultMark,
        clock: &dyn pos_owner_bridge::MonotonicClock,
        callback_order: Box<dyn FnOnce() -> Vec<crate::NativeCallbackMoment> + '_>,
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
                if clock.now() >= self.deadline {
                    return Err("pending-opening browser exit timed out".into());
                }
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
            if clock.now() >= self.deadline {
                return Err("pending-opening browser exit timed out".into());
            }
            readiness::pump(&self.surface)?;
        }
        loop {
            if let Some(success) = self.surface.pending_opening_completion() {
                if !controller_invoked_after_exit(&callback_order(), browser.browser_pid) {
                    return Err(
                        "controller completion was not invoked after the matching exit".into(),
                    );
                }
                if clock.now() >= self.deadline {
                    return Err("late controller completion was not observed".into());
                }
                self.trace
                    .borrow_mut()
                    .push(ProcessFaultMark::ControllerCompletion(success));
                self.evidence_complete = true;
                return Ok(());
            }
            if clock.now() >= self.deadline {
                return Err("late controller completion was not observed".into());
            }
            readiness::pump(&self.surface)?;
        }
    }
}

fn run_first_opening_browser(
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
        fixture.drive_first_opening_browser(&mut driver, inject)
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
        return Err("opening failure, wipe, or evidence was not established".into());
    }
    first.ok_or_else(|| "opening cutpoint was not reached".into())
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
            if let (None, Step::Pending, Some(receipt)) =
                (self.reached, &step, driver.first_receipt_at())
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
                        self.at_posted_writing(driver, target, inject, receipt)?;
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
        receipt: Instant,
    ) -> TestResult {
        let deadline = interaction_deadline(self.deadline, receipt);
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
            self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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
            if let (None, Some(receipt)) = (self.reached, driver.first_receipt_at()) {
                let state = self
                    .surface
                    .reply_load_state()
                    .map_err(|_| "ready reply read failed")?;
                if state == ControlState::Ready as u32 {
                    self.at_posted_ready(driver, target, inject, receipt)?;
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
        receipt: Instant,
    ) -> TestResult {
        let deadline = interaction_deadline(self.deadline, receipt);
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
            self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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
                    self.observe_fault_until(target, ProcessFaultMark::Reached(state), deadline)?;
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
        self.on_consuming_with_clock(&SystemClock)
    }

    fn on_consuming_with_clock(&self, clock: &dyn pos_owner_bridge::MonotonicClock) -> TestResult {
        if *self.reached.borrow() {
            return Err("consuming CAS was observed twice".into());
        }
        if clock.now() >= self.deadline {
            return Err("consuming fault point expired".into());
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
        self.observe_consuming_with_clock(state, &SystemClock)
    }

    fn observe_consuming_with_clock(
        &self,
        state: ProcessFaultState,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        loop {
            if clock.now() >= self.deadline {
                return Err("consuming event timed out".into());
            }
            if let Some(event) = self
                .inner
                .borrow()
                .posted_fault_event(self.target)
                .map_err(|()| "consuming fault event mismatched")?
            {
                let held = self.handle.borrow();
                let handle = held.as_ref().ok_or("consuming fault handle missing")?;
                let identity = handle.identity();
                let code = require_exit_code(
                    handle.exit_code(),
                    "consuming exit query failed",
                    "consuming exit still pending",
                )?;
                if clock.now() >= self.deadline {
                    return Err("consuming event timed out".into());
                }
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
            let receipt = driver.first_receipt_at().filter(|_| self.reached.is_none());
            let ready = if receipt.is_some() {
                self.surface
                    .reply_load_state()
                    .map_err(|_| "consuming reply read failed")?
                    == ControlState::Ready as u32
            } else {
                false
            };
            if let (Some(receipt), true) = (receipt, ready) {
                let state = self
                    .surface
                    .posted_ready_fault_state(driver.posts())
                    .map_err(|()| "pre-consuming state unavailable")?;
                let deadline = interaction_deadline(self.deadline, receipt);
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
        self.on_write_with_clock(record, &SystemClock)
    }

    fn on_write_with_clock(
        &mut self,
        record: &[u8],
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        if self.reached {
            return Err("record write observed twice".into());
        }
        if clock.now() >= self.deadline {
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
        if clock.now() >= self.deadline {
            return Err("pre-record point expired".into());
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
        self.observe_before_record_with_clock(browser, first, &SystemClock)
    }

    fn observe_before_record_with_clock(
        &self,
        browser: pos_owner_bridge::ProcessIdentity,
        first: ProcessFaultMark,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        loop {
            if clock.now() >= self.deadline {
                return Err("pre-record browser exit timed out".into());
            }
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
                let code = require_exit_code(
                    handle.exit_code(),
                    "pre-record exit query failed",
                    "pre-record process exit pending",
                )?;
                if clock.now() >= self.deadline {
                    return Err("pre-record browser exit timed out".into());
                }
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
                    self.record_control_observation(mark, Some(presence), &SystemClock)?;
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
        self.observe_early_renderer_with_clock(first, &SystemClock)
    }

    fn observe_early_renderer_with_clock(
        &mut self,
        first: ProcessFaultMark,
        clock: &dyn pos_owner_bridge::MonotonicClock,
    ) -> TestResult {
        loop {
            if clock.now() >= self.deadline {
                return Err("early renderer event timed out".into());
            }
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
                let code = require_exit_code(
                    held.exit_code(),
                    "early renderer exit query failed",
                    "early renderer exit pending",
                )?;
                if clock.now() >= self.deadline {
                    return Err("early renderer event timed out".into());
                }
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
    Cancellation,
    Timeout,
}

fn clean_environment_callback_order(
    order: &[crate::NativeCallbackMoment],
    case: EnvironmentCase,
) -> bool {
    use crate::NativeCallbackMoment::{DriverTimeout, EnvironmentCompletion};
    match case {
        EnvironmentCase::Cancellation => order == [EnvironmentCompletion(true)],
        EnvironmentCase::Timeout => {
            order == [EnvironmentCompletion(true), DriverTimeout]
                || order == [DriverTimeout, EnvironmentCompletion(true)]
        }
    }
}

#[test]
fn clean_environment_callback_order_preserves_actual_invocation() {
    use crate::NativeCallbackMoment::{DriverTimeout, EnvironmentCompletion, Overflow};
    assert!(clean_environment_callback_order(
        &[EnvironmentCompletion(true)],
        EnvironmentCase::Cancellation
    ));
    assert!(clean_environment_callback_order(
        &[EnvironmentCompletion(true), DriverTimeout],
        EnvironmentCase::Timeout
    ));
    assert!(clean_environment_callback_order(
        &[DriverTimeout, EnvironmentCompletion(true)],
        EnvironmentCase::Timeout
    ));
    assert!(!clean_environment_callback_order(
        &[DriverTimeout],
        EnvironmentCase::Timeout
    ));
    assert!(!clean_environment_callback_order(
        &[EnvironmentCompletion(false)],
        EnvironmentCase::Cancellation
    ));
    assert!(!clean_environment_callback_order(
        &[EnvironmentCompletion(true), EnvironmentCompletion(true)],
        EnvironmentCase::Cancellation
    ));
    assert!(!clean_environment_callback_order(
        &[EnvironmentCompletion(true), DriverTimeout, Overflow],
        EnvironmentCase::Timeout
    ));
}

#[test]
fn modeled_callback_witnesses_bound_repeated_observations_and_reset() {
    use crate::{CreationCallback, Native, NativeCallbackMoment, NativeCreationMoment};
    let callback = NativeCallbackMoment::EnvironmentCompletion(true);
    Native::arm_callback_order();
    for _ in 0..68 {
        Native::record_callback(callback);
    }
    let callbacks = Native::callback_order();
    assert_eq!(&callbacks[..64], vec![callback; 64]);
    assert_eq!(&callbacks[64..], [NativeCallbackMoment::Overflow]);
    Native::disarm_callback_order();
    Native::record_callback(callback);
    assert!(Native::callback_order().is_empty());
    Native::arm_callback_order();
    assert!(Native::callback_order().is_empty());
    Native::disarm_callback_order();

    let creation = NativeCreationMoment::EnvironmentCallback(CreationCallback::Success);
    Native::arm_creation_order();
    for _ in 0..36 {
        Native::creation_moment(creation);
    }
    let creations = Native::creation_order();
    assert_eq!(&creations[..32], vec![creation; 32]);
    assert_eq!(&creations[32..], [NativeCreationMoment::Overflow]);
    Native::disarm_creation_order();
    Native::creation_moment(creation);
    assert!(Native::creation_order().is_empty());
    Native::arm_creation_order();
    assert!(Native::creation_order().is_empty());
    Native::disarm_creation_order();
}

#[test]
fn native_environment_result_retained_through_cancellation() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_pre_environment(Path::new(&runtime), 0x7e, EnvironmentCase::Cancellation)
}

#[test]
fn native_environment_result_retained_through_readiness_timeout() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_pre_environment(Path::new(&runtime), 0x7f, EnvironmentCase::Timeout)
}

struct PreEnvironmentDrive {
    result: CeremonyResult,
    driver_pending: bool,
    active_blocked: bool,
    initial_completion: Result<Option<bool>, ()>,
    pump_failed: bool,
    boundary_completion: Result<Option<bool>, ()>,
}

#[derive(Clone, Copy)]
struct PreEnvironmentStart {
    driver_pending: bool,
    active_blocked: bool,
    pump_failed: bool,
    initial_completion: Result<Option<bool>, ()>,
    boundary_completion: Result<Option<bool>, ()>,
}

/// Captured observations used only after the native owner has been retired.
#[derive(Clone, Copy)]
struct PreEnvironmentEvidence<'a> {
    start: PreEnvironmentStart,
    case: EnvironmentCase,
    termination: Option<BridgeError>,
    wiped: bool,
    callbacks: &'a [crate::NativeCallbackMoment],
    creation: &'a [crate::NativeCreationMoment],
    retirement: EnvironmentRetirementEvidence,
    record: EnvironmentRecordEvidence,
}

fn expected_pre_environment_termination(case: EnvironmentCase, error: Option<BridgeError>) -> bool {
    use pos_owner_bridge::LifecycleCode;
    match case {
        EnvironmentCase::Timeout => {
            error == Some(BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout))
        }
        EnvironmentCase::Cancellation => {
            error == Some(BridgeError::Lifecycle(LifecycleCode::ControllerLost))
        }
    }
}

impl PreEnvironmentEvidence<'_> {
    fn validate(self) -> TestResult {
        let initial_witness = self.start.driver_pending
            && matches!(self.start.initial_completion, Ok(None | Some(true)));
        let expected_termination =
            expected_pre_environment_termination(self.case, self.termination);
        let ordered = clean_environment_callback_order(self.callbacks, self.case);
        let sdk_success = sdk_environment_result(self.creation, crate::CreationCallback::Success);
        if !initial_witness
            || !self.start.active_blocked
            || !self.retirement.abandoned_blocked
            || self.start.pump_failed
            || !expected_termination
            || !self.wiped
            || !self.retirement.no_resurrection
            || !ordered
            || !sdk_success
            || !self.record.no_record
            || !self.record.retained_orphan
            || !self.retirement.idle
        {
            let Self {
                start,
                retirement,
                record,
                wiped,
                ..
            } = self;
            return Err(format!("pre-environment witness failed: driver_pending={} active_blocked={} abandoned_blocked={} initial_completion={:?} completion={:?} expected_termination={} wiped={} ordered={} no_record={} retained_orphan={} idle={}", start.driver_pending, start.active_blocked, retirement.abandoned_blocked, start.initial_completion, start.boundary_completion, expected_termination, wiped, ordered, record.no_record, record.retained_orphan, retirement.idle).into());
        }
        Ok(())
    }
}

#[test]
fn modeled_pre_environment_verdict_refuses_missing_evidence_after_retirement() {
    use crate::NativeCallbackMoment::{DriverTimeout, EnvironmentCompletion};
    use crate::NativeCreationMoment::{EnvironmentCallback, EnvironmentReturned};
    use pos_owner_bridge::LifecycleCode::{ControllerLost, ReadinessTimeout};
    type Change = fn(&mut PreEnvironmentEvidence<'static>);
    let success = PreEnvironmentEvidence {
        start: PreEnvironmentStart {
            driver_pending: true,
            active_blocked: true,
            pump_failed: false,
            initial_completion: Ok(None),
            boundary_completion: Ok(Some(true)),
        },
        case: EnvironmentCase::Cancellation,
        termination: Some(BridgeError::Lifecycle(ControllerLost)),
        wiped: true,
        callbacks: &[EnvironmentCompletion(true)],
        creation: &[
            EnvironmentReturned(true),
            EnvironmentCallback(crate::CreationCallback::Success),
        ],
        retirement: EnvironmentRetirementEvidence {
            no_resurrection: true,
            abandoned_blocked: true,
            idle: true,
        },
        record: EnvironmentRecordEvidence {
            no_record: true,
            retained_orphan: true,
        },
    };
    assert!(success.validate().is_ok());
    assert!(PreEnvironmentEvidence {
        case: EnvironmentCase::Timeout,
        termination: Some(BridgeError::Lifecycle(ReadinessTimeout)),
        callbacks: &[EnvironmentCompletion(true), DriverTimeout],
        start: PreEnvironmentStart {
            initial_completion: Ok(Some(true)),
            ..success.start
        },
        ..success
    }
    .validate()
    .is_ok());
    let contradictions: [(&str, Change); 13] = [
        ("driver not pending", |e| {
            e.start.driver_pending = false;
        }),
        ("admission unblocked", |e| {
            e.start.active_blocked = false;
        }),
        ("pump failed", |e| {
            e.start.pump_failed = true;
        }),
        ("initial callback failed", |e| {
            e.start.initial_completion = Ok(Some(false));
        }),
        ("initial observation invalid", |e| {
            e.start.initial_completion = Err(());
        }),
        ("wrong termination", |e| {
            e.termination = Some(BridgeError::Lifecycle(ReadinessTimeout));
        }),
        ("unwiped", |e| {
            e.wiped = false;
        }),
        ("callback order wrong", |e| {
            e.callbacks = &[DriverTimeout, EnvironmentCompletion(true)];
        }),
        ("SDK evidence absent", |e| {
            e.creation = &[EnvironmentReturned(false)];
        }),
        ("driver resurrected", |e| {
            e.retirement.no_resurrection = false;
        }),
        ("abandoned admission unblocked", |e| {
            e.retirement.abandoned_blocked = false;
        }),
        ("record retained", |e| {
            e.record.no_record = false;
        }),
        ("orphan missing", |e| {
            e.record.retained_orphan = false;
        }),
    ];
    for (label, change) in contradictions {
        let mut evidence = success;
        change(&mut evidence);
        assert!(evidence.validate().is_err(), "{label}");
    }
    let mut not_idle = success;
    not_idle.retirement.idle = false;
    assert_eq!(
        not_idle.validate().err().map(|error| error.to_string()).as_deref(),
        Some("pre-environment witness failed: driver_pending=true active_blocked=true abandoned_blocked=true initial_completion=Ok(None) completion=Ok(Some(true)) expected_termination=true wiped=true ordered=true no_record=true retained_orphan=true idle=false")
    );
}

impl Fixture {
    fn finished_driver_is_done(&mut self, driver: &mut CeremonyDriver) -> bool {
        matches!(
            driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            )),
            Step::Done
        )
    }

    fn drive_pre_environment(
        &mut self,
        driver: &mut CeremonyDriver,
        started: Instant,
        case: EnvironmentCase,
    ) -> PreEnvironmentDrive {
        let initial = driver.step(&mut readiness::env(
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
        ));
        let driver_pending = matches!(initial, Step::Pending);
        let initial_completion = self.surface.pre_environment_completion();
        let active_blocked = self.pre_environment_competitor_blocked(
            &CeremonyId::from_bytes([self.number; 16]),
            crate::adapter::surface::PreEnvironmentRetention::Active,
        );
        // The original deadline remains unchanged; no callback is delayed.
        let deadline = started + pos_owner_bridge::ceremony::timing::READINESS;
        let mut pump_failed = false;
        if matches!(case, EnvironmentCase::Timeout) {
            while Instant::now() < deadline {
                pump_failed |= readiness::pump(&self.surface).is_err();
            }
        }
        let boundary_completion = self.surface.pre_environment_completion();
        let result = if matches!(case, EnvironmentCase::Timeout) {
            let result = match driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            )) {
                Step::Finished(result) => result,
                _ => readiness::cancel_driver(
                    driver,
                    &mut self.surface,
                    &mut self.loopback,
                    &mut self.store,
                ),
            };
            crate::Native::record_callback(crate::NativeCallbackMoment::DriverTimeout);
            result
        } else {
            readiness::cancel_driver(
                driver,
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            )
        };
        PreEnvironmentDrive {
            result,
            driver_pending,
            active_blocked,
            initial_completion,
            pump_failed,
            boundary_completion,
        }
    }
}

fn run_pre_environment(runtime: &Path, number: u8, case: EnvironmentCase) -> TestResult {
    let root = FixtureRoot::new()?;
    let callback_order_guard = CallbackOrderGuard::arm();
    let creation_order_guard = CreationOrderGuard::arm();
    let mut fixture = Fixture::new(runtime, &root.0, number, FixtureProfile::Pending)?;
    let started = Instant::now();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), started)?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_pre_environment(&mut driver, started, case)
    }));
    let PreEnvironmentDrive {
        result,
        driver_pending,
        active_blocked,
        initial_completion,
        pump_failed,
        boundary_completion,
    } = match attempt {
        Ok(observation) => observation,
        Err(_) => PreEnvironmentDrive {
            result: readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            driver_pending: false,
            active_blocked: false,
            initial_completion: Err(()),
            pump_failed: true,
            boundary_completion: Err(()),
        },
    };
    let initial_witness = driver_pending && matches!(initial_completion, Ok(None | Some(true)));
    let termination = result.as_ref().err().copied();
    let expected_termination = expected_pre_environment_termination(case, termination);
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    fixture.surface.abandon_opening();
    let abandoned_blocked = catch_unwind(AssertUnwindSafe(|| {
        fixture.pre_environment_competitor_blocked(
            &CeremonyId::from_bytes([number; 16]),
            crate::adapter::surface::PreEnvironmentRetention::Abandoned,
        )
    }))
    .unwrap_or(false);
    let no_resurrection = fixture.finished_driver_is_done(&mut driver);
    // Retirement consumes the actual retained SDK result; it may already be delivered.
    retirement::retire(
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
        driver,
        result,
        |_, _, _| {},
    );
    let order = crate::Native::callback_order();
    let ordered = clean_environment_callback_order(&order, case);
    let creation_order = crate::Native::creation_order();
    let sdk_success = sdk_environment_result(&creation_order, crate::CreationCallback::Success);
    let no_record = fixture.store.records()?.is_empty();
    let retained_orphan = fixture.store.folders()?.len() == 1;
    let idle = fixture.surface.idle();
    let evidence = PreEnvironmentEvidence {
        start: PreEnvironmentStart {
            driver_pending,
            active_blocked,
            pump_failed,
            initial_completion,
            boundary_completion,
        },
        case,
        termination,
        wiped,
        callbacks: &order,
        creation: &creation_order,
        retirement: EnvironmentRetirementEvidence {
            no_resurrection,
            abandoned_blocked,
            idle,
        },
        record: EnvironmentRecordEvidence {
            no_record,
            retained_orphan,
        },
    };
    let _logged = writeln!(std::io::stderr(), "NATIVE_PRE_ENV_VERDICT case={number} initial_witness={initial_witness} driver_pending={driver_pending} active_blocked={active_blocked} abandoned_blocked={abandoned_blocked} initial_completion={initial_completion:?} boundary_completion={boundary_completion:?} pump_failed={pump_failed} expected_termination={expected_termination} wiped={wiped} order={order:?} creation_order={creation_order:?} sdk_success={sdk_success} no_resurrection={no_resurrection} ordered={ordered} no_record={no_record} orphan={retained_orphan} idle={idle}");
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("pre-environment factory still shared")?
        .stop()?;
    // No process/exit was established. Preserve the recordless folder for real
    // later recovery; neither an orphan sweep nor remove_dir_all is evidence.
    evidence.validate()?;
    drop(callback_order_guard);
    drop(creation_order_guard);
    if matches!(case, EnvironmentCase::Timeout) {
        // Surface held one clone; release the fixture's last listener owner
        // before the next ceremony binds the same exclusive loopback port.
        drop(fixture.loopback);
        fresh_success_after_retirement(runtime, &root.0, 0xd2)?;
    }
    Ok(())
}

struct CreationOrderGuard;

impl CreationOrderGuard {
    fn arm() -> Self {
        crate::Native::arm_creation_order();
        Self
    }
}

impl Drop for CreationOrderGuard {
    fn drop(&mut self) {
        crate::Native::disarm_creation_order();
    }
}

fn sdk_environment_result(
    order: &[crate::NativeCreationMoment],
    callback: crate::CreationCallback,
) -> bool {
    use crate::NativeCreationMoment::{EnvironmentCallback, EnvironmentReturned};
    order == [EnvironmentReturned(true), EnvironmentCallback(callback)]
        || order == [EnvironmentCallback(callback), EnvironmentReturned(true)]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnvironmentSdkOutcome {
    Success,
    NativeFailure,
    InitiationRefused,
}

fn environment_sdk_outcome(order: &[crate::NativeCreationMoment]) -> Option<EnvironmentSdkOutcome> {
    use crate::CreationCallback::{NativeFailure, Success};
    use crate::NativeCreationMoment::EnvironmentReturned;
    if sdk_environment_result(order, Success) {
        Some(EnvironmentSdkOutcome::Success)
    } else if sdk_environment_result(order, NativeFailure) {
        Some(EnvironmentSdkOutcome::NativeFailure)
    } else if order == [EnvironmentReturned(false)] {
        Some(EnvironmentSdkOutcome::InitiationRefused)
    } else {
        None
    }
}

#[test]
fn sdk_outcome_distinguishes_refusal_failure_and_success() {
    use crate::CreationCallback::{Inconsistent, MissingInterface, NativeFailure, Success};
    use crate::NativeCreationMoment::{
        ControllerReturned, EnvironmentCallback, EnvironmentReturned, Overflow,
    };
    assert_eq!(
        environment_sdk_outcome(&[EnvironmentReturned(false)]),
        Some(EnvironmentSdkOutcome::InitiationRefused)
    );
    for (result, expected) in [
        (Success, EnvironmentSdkOutcome::Success),
        (NativeFailure, EnvironmentSdkOutcome::NativeFailure),
    ] {
        assert_eq!(
            environment_sdk_outcome(&[EnvironmentReturned(true), EnvironmentCallback(result)]),
            Some(expected)
        );
        assert_eq!(
            environment_sdk_outcome(&[EnvironmentCallback(result), EnvironmentReturned(true)]),
            Some(expected)
        );
    }
    for order in [
        vec![],
        vec![EnvironmentReturned(true)],
        vec![
            EnvironmentReturned(false),
            EnvironmentCallback(NativeFailure),
        ],
        vec![
            EnvironmentReturned(true),
            EnvironmentCallback(MissingInterface),
        ],
        vec![EnvironmentReturned(true), EnvironmentCallback(Inconsistent)],
        vec![
            EnvironmentReturned(true),
            EnvironmentCallback(Success),
            EnvironmentCallback(Success),
        ],
        vec![
            EnvironmentReturned(true),
            EnvironmentCallback(Success),
            Overflow,
        ],
        vec![
            EnvironmentReturned(true),
            EnvironmentCallback(Success),
            ControllerReturned(true),
        ],
    ] {
        assert_eq!(environment_sdk_outcome(&order), None);
    }
}

#[test]
fn creation_witness_rejects_sync_error_and_false_failure() {
    use crate::CreationCallback::{Inconsistent, MissingInterface, NativeFailure, Success};
    use crate::NativeCreationMoment::{EnvironmentCallback, EnvironmentReturned};
    assert!(sdk_environment_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(NativeFailure)
        ],
        NativeFailure
    ));
    assert!(!sdk_environment_result(
        &[EnvironmentReturned(false)],
        NativeFailure
    ));
    assert!(!sdk_environment_result(
        &[
            EnvironmentReturned(false),
            EnvironmentCallback(NativeFailure)
        ],
        NativeFailure,
    ));
    assert!(!sdk_environment_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(NativeFailure),
            crate::NativeCreationMoment::Overflow
        ],
        NativeFailure,
    ));
    assert!(!sdk_environment_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(NativeFailure),
            crate::NativeCreationMoment::ControllerReturned(true)
        ],
        NativeFailure,
    ));
    assert!(!sdk_environment_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(NativeFailure),
            EnvironmentCallback(NativeFailure)
        ],
        NativeFailure,
    ));
    assert!(sdk_environment_result(
        &[
            EnvironmentCallback(NativeFailure),
            EnvironmentReturned(true)
        ],
        NativeFailure
    ));
    assert!(!sdk_environment_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(MissingInterface)
        ],
        NativeFailure
    ));
    assert!(!sdk_environment_result(
        &[EnvironmentReturned(true), EnvironmentCallback(Inconsistent)],
        NativeFailure
    ));
    assert!(!sdk_environment_result(
        &[EnvironmentReturned(true), EnvironmentCallback(Success)],
        NativeFailure
    ));
}

#[test]
fn native_obstructed_environment_creation_and_retirement() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    run_environment_obstruction(Path::new(&runtime), &root.0, 0x80, false)?;
    run_environment_obstruction(Path::new(&runtime), &root.0, 0x81, true)
}

type EnvironmentDriveResult =
    Result<(CeremonyResult, bool, bool, Result<Option<bool>, ()>), Box<dyn std::error::Error>>;

/// Captured evidence only; this validator does not create or alter SDK observations.
#[derive(Clone, Copy)]
struct EnvironmentObstructionEvidence {
    obstruct: bool,
    outcome: Option<EnvironmentSdkOutcome>,
    completion: Result<Option<bool>, ()>,
    opening: EnvironmentOpeningEvidence,
    retirement: EnvironmentRetirementEvidence,
    wipe: EnvironmentWipeEvidence,
    record: EnvironmentRecordEvidence,
}

#[derive(Clone, Copy)]
struct EnvironmentOpeningEvidence {
    driver_pending: bool,
    active_blocked: bool,
    attempt_failed: bool,
}

#[derive(Clone, Copy)]
struct EnvironmentRetirementEvidence {
    no_resurrection: bool,
    abandoned_blocked: bool,
    idle: bool,
}

#[derive(Clone, Copy)]
struct EnvironmentWipeEvidence {
    wiped: bool,
    result_failed: bool,
    plan_wiped: bool,
}

#[derive(Clone, Copy)]
struct EnvironmentRecordEvidence {
    no_record: bool,
    retained_orphan: bool,
}

impl EnvironmentObstructionEvidence {
    fn validate(self) -> TestResult {
        let qualified_outcome = match self.outcome {
            Some(EnvironmentSdkOutcome::Success) => {
                self.opening.driver_pending
                    && self.opening.active_blocked
                    && matches!(self.completion, Ok(None | Some(true)))
            }
            Some(EnvironmentSdkOutcome::NativeFailure) if self.obstruct => {
                self.opening.driver_pending
                    && self.opening.active_blocked
                    && matches!(self.completion, Ok(None | Some(false)))
            }
            Some(EnvironmentSdkOutcome::InitiationRefused) if self.obstruct => {
                !self.opening.driver_pending && self.completion.is_err()
            }
            _ => false,
        };
        if self.opening.attempt_failed
            || !qualified_outcome
            || !self.retirement.no_resurrection
            || !self.retirement.abandoned_blocked
            || !self.wipe.wiped
            || !self.wipe.result_failed
            || !self.wipe.plan_wiped
            || !self.record.no_record
            || !self.record.retained_orphan
            || !self.retirement.idle
        {
            return Err(
                "native environment input outcome or retained ownership was not established".into(),
            );
        }
        Ok(())
    }
}

fn modeled_environment_obstruction_success() -> EnvironmentObstructionEvidence {
    EnvironmentObstructionEvidence {
        obstruct: false,
        outcome: Some(EnvironmentSdkOutcome::Success),
        completion: Ok(Some(true)),
        opening: EnvironmentOpeningEvidence {
            driver_pending: true,
            active_blocked: true,
            attempt_failed: false,
        },
        retirement: EnvironmentRetirementEvidence {
            no_resurrection: true,
            abandoned_blocked: true,
            idle: true,
        },
        wipe: EnvironmentWipeEvidence {
            wiped: true,
            result_failed: true,
            plan_wiped: true,
        },
        record: EnvironmentRecordEvidence {
            no_record: true,
            retained_orphan: true,
        },
    }
}

#[test]
fn modeled_environment_obstruction_verdict_checks_sdk_outcomes() {
    type Change = fn(&mut EnvironmentObstructionEvidence);
    let success = modeled_environment_obstruction_success();
    assert!(success.validate().is_ok());
    assert!(EnvironmentObstructionEvidence {
        completion: Ok(None),
        ..success
    }
    .validate()
    .is_ok());
    let failed_callback = EnvironmentObstructionEvidence {
        obstruct: true,
        outcome: Some(EnvironmentSdkOutcome::NativeFailure),
        completion: Ok(Some(false)),
        ..success
    };
    assert!(failed_callback.validate().is_ok());
    assert!(EnvironmentObstructionEvidence {
        completion: Ok(None),
        ..failed_callback
    }
    .validate()
    .is_ok());
    let refused = EnvironmentObstructionEvidence {
        outcome: Some(EnvironmentSdkOutcome::InitiationRefused),
        completion: Err(()),
        opening: EnvironmentOpeningEvidence {
            driver_pending: false,
            ..success.opening
        },
        ..failed_callback
    };
    assert!(refused.validate().is_ok());
    let contradictions: [(&str, EnvironmentObstructionEvidence, Change); 12] = [
        ("missing outcome", success, |e| e.outcome = None),
        ("failed success completion", success, |e| {
            e.completion = Err(());
        }),
        ("false success completion", success, |e| {
            e.completion = Ok(Some(false));
        }),
        ("success without pending", success, |e| {
            e.opening.driver_pending = false;
        }),
        ("success without blocked admission", success, |e| {
            e.opening.active_blocked = false;
        }),
        ("unobstructed native failure", failed_callback, |e| {
            e.obstruct = false;
        }),
        ("failure with success completion", failed_callback, |e| {
            e.completion = Ok(Some(true));
        }),
        ("failure without pending", failed_callback, |e| {
            e.opening.driver_pending = false;
        }),
        ("failure without blocked admission", failed_callback, |e| {
            e.opening.active_blocked = false;
        }),
        ("unobstructed initiation refusal", refused, |e| {
            e.obstruct = false;
        }),
        ("refusal with completion", refused, |e| {
            e.completion = Ok(None);
        }),
        ("refusal with pending", refused, |e| {
            e.opening.driver_pending = true;
        }),
    ];
    for (label, mut evidence, change) in contradictions {
        change(&mut evidence);
        assert_environment_obstruction_refused(evidence, label);
    }
}

#[test]
fn modeled_environment_obstruction_verdict_requires_retained_custody() {
    type Change = fn(&mut EnvironmentObstructionEvidence);
    let contradictions: [(&str, Change); 9] = [
        ("attempt failed", |e| e.opening.attempt_failed = true),
        ("driver resurrected", |e| {
            e.retirement.no_resurrection = false;
        }),
        ("abandoned admission unblocked", |e| {
            e.retirement.abandoned_blocked = false;
        }),
        ("request not wiped", |e| e.wipe.wiped = false),
        ("successful ceremony result", |e| {
            e.wipe.result_failed = false;
        }),
        ("plan not wiped", |e| e.wipe.plan_wiped = false),
        ("record present", |e| e.record.no_record = false),
        ("orphan not retained", |e| e.record.retained_orphan = false),
        ("surface not idle", |e| e.retirement.idle = false),
    ];
    for (label, change) in contradictions {
        let mut evidence = modeled_environment_obstruction_success();
        change(&mut evidence);
        assert_environment_obstruction_refused(evidence, label);
    }
}

fn assert_environment_obstruction_refused(evidence: EnvironmentObstructionEvidence, label: &str) {
    assert_eq!(
        evidence
            .validate()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("native environment input outcome or retained ownership was not established"),
        "{label}"
    );
}

impl Fixture {
    fn drive_environment_obstruction(
        &mut self,
        driver: &mut CeremonyDriver,
    ) -> EnvironmentDriveResult {
        let initial = driver.step(&mut readiness::env(
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
        ));
        let driver_pending = matches!(initial, Step::Pending);
        let mut observation = self.surface.pre_environment_completion();
        let active_blocked = self.pre_environment_competitor_blocked(
            &CeremonyId::from_bytes([self.number; 16]),
            crate::adapter::surface::PreEnvironmentRetention::Active,
        );
        while matches!(observation, Ok(None)) && Instant::now() < self.deadline {
            readiness::pump(&self.surface)?;
            observation = self.surface.pre_environment_completion();
        }
        let result = match initial {
            Step::Finished(result) => result,
            Step::Done => return Err("environment driver ended without a result".into()),
            Step::Pending => readiness::cancel_driver(
                driver,
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ),
        };
        Ok::<_, Box<dyn std::error::Error>>((result, driver_pending, active_blocked, observation))
    }
}

fn run_environment_obstruction(
    runtime: &Path,
    root: &Path,
    number: u8,
    obstruct: bool,
) -> TestResult {
    let _creation = CreationOrderGuard::arm();
    let mut fixture = if obstruct {
        Fixture::new_obstructed(runtime, root, number)?
    } else {
        Fixture::new(runtime, root, number, FixtureProfile::Pending)?
    };
    let started = Instant::now();
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), started)?;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_environment_obstruction(&mut driver)
    }));
    let (result, driver_pending, active_blocked, observation, failed) = match attempt {
        Ok(Ok((result, pending, active_blocked, observation))) => {
            (result, pending, active_blocked, observation, false)
        }
        _ => (
            readiness::cancel_driver(
                &mut driver,
                &mut fixture.surface,
                &mut fixture.loopback,
                &mut fixture.store,
            ),
            false,
            false,
            Err(()),
            true,
        ),
    };
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let result_failed = result.is_err();
    let plan_wiped =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    fixture.surface.abandon_opening();
    let abandoned_blocked = catch_unwind(AssertUnwindSafe(|| {
        fixture.pre_environment_competitor_blocked(
            &CeremonyId::from_bytes([number; 16]),
            crate::adapter::surface::PreEnvironmentRetention::Abandoned,
        )
    }))
    .unwrap_or(false);
    let no_resurrection = fixture.finished_driver_is_done(&mut driver);
    retirement::retire(
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
        driver,
        result,
        |_, _, _| {},
    );
    let order = crate::Native::creation_order();
    let outcome = environment_sdk_outcome(&order);
    let no_record = fixture.store.records()?.is_empty();
    let retained_orphan = fixture.store.folders()?.len() == 1;
    let idle = fixture.surface.idle();
    let evidence = EnvironmentObstructionEvidence {
        obstruct,
        outcome,
        completion: observation,
        opening: EnvironmentOpeningEvidence {
            driver_pending,
            active_blocked,
            attempt_failed: failed,
        },
        retirement: EnvironmentRetirementEvidence {
            no_resurrection,
            abandoned_blocked,
            idle,
        },
        wipe: EnvironmentWipeEvidence {
            wiped,
            result_failed,
            plan_wiped,
        },
        record: EnvironmentRecordEvidence {
            no_record,
            retained_orphan,
        },
    };
    let _written = writeln!(std::io::stderr(), "NATIVE_UDF_OBSTRUCTION fixed_ebwebview_file_requested={obstruct} obstruct={obstruct} pending={driver_pending} active_blocked={active_blocked} abandoned_blocked={abandoned_blocked} completion={observation:?} order={order:?} outcome={outcome:?} no_resurrection={no_resurrection} wiped={wiped} idle={idle} orphan={retained_orphan}");
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("obstructed factory still shared")?
        .stop()?;
    evidence.validate()
}

fn sdk_controller_result(
    order: &[crate::NativeCreationMoment],
    callback: crate::CreationCallback,
) -> bool {
    use crate::CreationCallback::Success;
    use crate::NativeCreationMoment::{ControllerCallback, ControllerReturned};
    let [environment_a, environment_b, controller_a, controller_b] = order else {
        return false;
    };
    sdk_environment_result(&[*environment_a, *environment_b], Success)
        && ((*controller_a == ControllerReturned(true)
            && *controller_b == ControllerCallback(callback))
            || (*controller_a == ControllerCallback(callback)
                && *controller_b == ControllerReturned(true)))
}

fn sdk_controller_pending(order: &[crate::NativeCreationMoment]) -> bool {
    let [first, second, controller] = order else {
        return false;
    };
    sdk_environment_result(&[*first, *second], crate::CreationCallback::Success)
        && *controller == crate::NativeCreationMoment::ControllerReturned(true)
}

#[test]
fn controller_failure_witness_rejects_missing_or_untrusted_completion() {
    use crate::CreationCallback::{Inconsistent, MissingInterface, NativeFailure, Success};
    use crate::NativeCreationMoment::{
        ControllerCallback, ControllerReturned, EnvironmentCallback, EnvironmentReturned,
    };
    let environment = [EnvironmentReturned(true), EnvironmentCallback(Success)];
    let expected = [
        environment[0],
        environment[1],
        ControllerReturned(true),
        ControllerCallback(NativeFailure),
    ];
    assert!(sdk_controller_pending(&expected[..3]));
    assert!(!sdk_controller_pending(&expected));
    assert!(!sdk_controller_pending(&[
        environment[0],
        environment[1],
        ControllerReturned(false)
    ]));
    assert!(!sdk_controller_pending(&[environment[0], environment[1]]));
    assert!(sdk_controller_result(&expected, NativeFailure));
    assert!(sdk_controller_result(
        &[
            environment[0],
            environment[1],
            ControllerCallback(NativeFailure),
            ControllerReturned(true)
        ],
        NativeFailure
    ));
    for callback in [Success, MissingInterface, Inconsistent] {
        assert!(!sdk_controller_result(
            &[
                environment[0],
                environment[1],
                ControllerReturned(true),
                ControllerCallback(callback)
            ],
            NativeFailure
        ));
    }
    assert!(!sdk_controller_result(
        &[environment[0], environment[1], ControllerReturned(false)],
        NativeFailure
    ));
    assert!(!sdk_controller_result(
        &[
            environment[0],
            environment[1],
            ControllerReturned(false),
            ControllerCallback(NativeFailure)
        ],
        NativeFailure,
    ));
    assert!(!sdk_controller_result(
        &[
            environment[0],
            environment[1],
            ControllerReturned(true),
            crate::NativeCreationMoment::Overflow
        ],
        NativeFailure,
    ));
    assert!(!sdk_controller_result(
        &[
            EnvironmentReturned(true),
            EnvironmentCallback(NativeFailure),
            ControllerReturned(true),
            ControllerCallback(NativeFailure)
        ],
        NativeFailure,
    ));
    assert!(!sdk_controller_result(
        &[
            expected[0],
            expected[1],
            expected[2],
            expected[3],
            expected[3]
        ],
        NativeFailure
    ));
}

fn successful_close_observed(close: Option<crate::adapter::surface::CloseObservation>) -> bool {
    close.is_some_and(|observation| {
        observation.removed.is_ok()
            && observation.closed.is_ok()
            && observation.buffers_closed
            && !observation.buffers_uncertain
            && observation.had_controller
    })
}

/// Captured fresh-success evidence; it never creates an SDK observation.
#[derive(Clone, Copy)]
struct FreshSuccessEvidence<'a> {
    verified: bool,
    close: Option<crate::adapter::surface::CloseObservation>,
    own_exit: bool,
    zero_observations: &'a [NativeZeroObservation],
    provenance: Option<pos_owner_bridge::ProcessIdentity>,
}

impl FreshSuccessEvidence<'_> {
    fn validate(&self) -> TestResult {
        if !self.verified
            || !successful_close_observed(self.close)
            || !self.own_exit
            || !native_zeroing_observed(self.zero_observations)
            || self.provenance.is_none()
        {
            return Err(
                "fresh verified success or its native retirement evidence was not established"
                    .into(),
            );
        }
        Ok(())
    }
}

#[test]
fn modeled_fresh_success_requires_complete_retirement_evidence() {
    use crate::adapter::surface::CloseObservation;
    let close = CloseObservation {
        removed: Ok(()),
        closed: Ok(()),
        buffers_closed: true,
        buffers_uncertain: false,
        had_controller: true,
    };
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
    let observations = [request, reply];
    let browser = pos_owner_bridge::ProcessIdentity {
        browser_pid: 42,
        creation_filetime: 1,
        image_path_sha256: pos_owner_bridge_codec::ImagePathSha256::from_bytes([7; 32]),
    };
    let evidence = FreshSuccessEvidence {
        verified: true,
        close: Some(close),
        own_exit: true,
        zero_observations: &observations,
        provenance: Some(browser),
    };
    assert!(evidence.validate().is_ok());
    let native_error = crate::NativeError {
        operation: crate::Operation::Subscription,
        failure: crate::Failure::CallFailed,
    };
    let invalid_closes = [
        None,
        Some(CloseObservation {
            removed: Err(native_error),
            ..close
        }),
        Some(CloseObservation {
            closed: Err(native_error),
            ..close
        }),
        Some(CloseObservation {
            buffers_closed: false,
            ..close
        }),
        Some(CloseObservation {
            buffers_uncertain: true,
            ..close
        }),
        Some(CloseObservation {
            had_controller: false,
            ..close
        }),
    ];
    for close in invalid_closes {
        let invalid = FreshSuccessEvidence { close, ..evidence };
        assert!(invalid.validate().is_err());
    }
    for invalid in [
        FreshSuccessEvidence {
            verified: false,
            ..evidence
        },
        FreshSuccessEvidence {
            own_exit: false,
            ..evidence
        },
        FreshSuccessEvidence {
            provenance: None,
            ..evidence
        },
        FreshSuccessEvidence {
            zero_observations: &observations[..1],
            ..evidence
        },
    ] {
        assert_eq!(
            invalid
                .validate()
                .err()
                .map(|error| error.to_string())
                .as_deref(),
            Some("fresh verified success or its native retirement evidence was not established")
        );
    }
}

fn fresh_success_after_retirement(runtime: &Path, root: &Path, number: u8) -> TestResult {
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::SuccessfulGet)?;
    let _zero_witness = ZeroWitness::arm();
    let ceremony = CeremonyId::from_bytes([number; 16]);
    let mut driver = readiness::new_driver(ceremony, Instant::now())?;
    let mut provenance = None;
    let mut failure_stage = None;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture.drive_fresh_success(&mut driver, ceremony, &mut provenance, &mut failure_stage)
    }));
    let attempt_stage = match &attempt {
        Ok(Ok(_)) => "driver_returned",
        Ok(Err(_)) => "fixture_error",
        Err(_) => "panic",
    };
    let _logged = writeln!(std::io::stderr(), "NATIVE_FRESH_SUCCESS case={number} attempt={attempt_stage} failure_stage={failure_stage:?} provenance={}", provenance.is_some());
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let receipt_on_time = driver
        .first_receipt_at()
        .is_some_and(|received| received < fixture.deadline);
    let verified = result.is_ok()
        && has_synthetic_success_prf(&driver)
        && driver.request_clear()
        && receipt_on_time;
    let close = fixture.surface.initial_close_observation();
    let closed = successful_close_observed(close);
    let own_exit =
        provenance.is_some_and(|browser| fixture.surface.fresh_success_own_exit(browser));
    let observations = crate::Native::take_native_zero_observations();
    let native_zeroed = native_zeroing_observed(&observations);
    let evidence = FreshSuccessEvidence {
        verified,
        close,
        own_exit,
        zero_observations: &observations,
        provenance,
    };
    let _logged = writeln!(std::io::stderr(), "NATIVE_FRESH_SUCCESS case={number} verified={verified} receipt_on_time={receipt_on_time} closed={closed} own_exit={own_exit} native_zeroed={native_zeroed} driver_error={:?}", result.as_ref().err());
    fixture.retire(driver, result, None)?;
    let classification = check_final_process_failures(None);
    if let Some(error) = failure {
        return Err(error);
    }
    classification?;
    evidence.validate()
}

impl Fixture {
    fn drive_fresh_success(
        &mut self,
        driver: &mut CeremonyDriver,
        ceremony: CeremonyId,
        provenance: &mut Option<pos_owner_bridge::ProcessIdentity>,
        failure_stage: &mut Option<&'static str>,
    ) -> DriveResult {
        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if provenance.is_none() && driver.posts() == 1 && matches!(&step, Step::Pending) {
                *provenance = Some(self.surface.fresh_success_provenance(ceremony).map_err(
                    |()| {
                        *failure_stage = Some("provenance");
                        "fresh ceremony record or generation did not match the owner"
                    },
                )?);
            }
            match step {
                Step::Finished(result) => return Ok(result),
                Step::Done => {
                    *failure_stage = Some("driver_done");
                    return Err("fresh success driver ended without result".into());
                }
                Step::Pending => {
                    if let Err(error) = readiness::pump(&self.surface) {
                        *failure_stage = Some("pump");
                        return Err(error);
                    }
                }
            }
        }
    }
}

impl Fixture {
    fn held_controller_result_blocked(
        &mut self,
        ceremony: &CeremonyId,
        completion: Option<bool>,
    ) -> bool {
        let expected = completion.map(|success| {
            (
                crate::adapter::surface::PreEnvironmentRetention::Abandoned,
                success,
            )
        });
        expected.is_some()
            && self.surface.controller_result_retention(ceremony) == expected
            && matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            && self.surface.controller_result_retention(ceremony) == expected
            && self.surface.pending_opening_completion() == completion
            && !self.surface.idle()
            && self.store.records().is_ok_and(|records| records.is_empty())
    }

    fn drive_controller_input(
        &mut self,
        driver: &mut CeremonyDriver,
        lose_parent: bool,
        lost_blocked: &mut bool,
    ) -> Result<(CeremonyResult, bool), Box<dyn std::error::Error>> {
        use crate::adapter::surface::PreEnvironmentRetention::{Abandoned, Active};

        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if matches!(&step, Step::Pending) && self.surface.recordless_opening_ready() {
                if driver.generation() != 1
                    || driver.posts() != 0
                    || !self.store.records()?.is_empty()
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || !self.surface.recordless_opening_ready()
                {
                    return Err("controller input did not retain active opening owners".into());
                }
                let ceremony = CeremonyId::from_bytes([self.number; 16]);
                if !sdk_controller_pending(&crate::Native::creation_order())
                    || self.surface.controller_creation_retention(&ceremony) != Some(Active)
                    || !matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                    || self.surface.controller_creation_retention(&ceremony) != Some(Active)
                {
                    return Err(
                        "uninvoked controller callback and retained owners not established".into(),
                    );
                }
                if lose_parent {
                    self.surface
                        .lose_pending_controller_parent(&ceremony)
                        .map_err(|()| "owned controller parent loss failed")?;
                    if Instant::now() >= self.deadline
                        || self.surface.lost_controller_parent_retention(&ceremony) != Some(Active)
                        || !sdk_controller_result(
                            &crate::Native::creation_order(),
                            crate::CreationCallback::NativeFailure,
                        )
                    {
                        return Err("parent loss did not produce actual native failure".into());
                    }
                    self.surface.abandon_opening();
                    *lost_blocked = self.surface.lost_controller_parent_retention(&ceremony)
                        == Some(Abandoned)
                        && matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
                        && self.surface.lost_controller_parent_retention(&ceremony)
                            == Some(Abandoned);
                    let result = readiness::cancel_driver(
                        driver,
                        &mut self.surface,
                        &mut self.loopback,
                        &mut self.store,
                    );
                    return Ok((result, false));
                }
                loop {
                    if let Some(success) = self.surface.pending_opening_completion() {
                        let ceremony = CeremonyId::from_bytes([self.number; 16]);
                        if self.surface.controller_result_retention(&ceremony)
                            != Some((
                                crate::adapter::surface::PreEnvironmentRetention::Active,
                                success,
                            ))
                        {
                            return Err("actual controller result owner was not retained".into());
                        }
                        let result = readiness::cancel_driver(
                            driver,
                            &mut self.surface,
                            &mut self.loopback,
                            &mut self.store,
                        );
                        return Ok((result, success));
                    }
                    if Instant::now() >= self.deadline {
                        return Err("actual controller callback was not observed".into());
                    }
                    readiness::pump(&self.surface)?;
                }
            }
            match step {
                Step::Finished(_) | Step::Done => {
                    return Err("controller input did not reach the pending stage".into())
                }
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
    }
}

fn run_controller_input_case(
    runtime: &Path,
    root: &Path,
    number: u8,
    lose_parent: bool,
) -> TestResult {
    let _creation = CreationOrderGuard::arm();
    crate::Native::reset_process_failure_observations();
    let mut fixture = Fixture::new(runtime, root, number, FixtureProfile::Pending)?;
    let mut driver = readiness::new_driver(CeremonyId::from_bytes([number; 16]), Instant::now())?;
    let mut completion = None;
    let mut lost_blocked = false;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture
            .drive_controller_input(&mut driver, lose_parent, &mut lost_blocked)
            .map(|(result, success)| {
                completion = Some(success);
                result
            })
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let failed = result.is_err();
    let plan_wiped =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    fixture.surface.abandon_opening();
    let ceremony = CeremonyId::from_bytes([number; 16]);
    let blocked = if lose_parent {
        lost_blocked
    } else {
        fixture.held_controller_result_blocked(&ceremony, completion)
    };
    let selected = if completion == Some(true) {
        fixture.surface.abandoned_completed_browser(&ceremony).ok()
    } else {
        None
    };
    let no_resurrection = fixture.finished_driver_is_done(&mut driver);
    retirement::retire(
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
        driver,
        result,
        |_, _, _| {},
    );
    let order = crate::Native::creation_order();
    let callback = if lose_parent {
        crate::CreationCallback::NativeFailure
    } else {
        crate::CreationCallback::Success
    };
    let sdk = sdk_controller_result(&order, callback);
    let matched_exit = selected.is_some()
        && fixture.surface.recordless_fault_event() == Ok(Some(ProcessFaultMark::OwnBrowserExited));
    let idle = fixture.surface.idle();
    let no_record = fixture.store.records()?.is_empty();
    let folders = fixture.store.folders()?;
    let expected_orphan = folders
        == [pos_owner_bridge::folder_name(&CeremonyId::from_bytes(
            [number; 16],
        ))];
    let orphan_count = folders.len();
    let _logged = writeln!(std::io::stderr(), "NATIVE_CONTROLLER_INPUT case={number} lose_parent={lose_parent} completion={completion:?} order={order:?} sdk={sdk} blocked={blocked} wiped={wiped} idle={idle} no_record={no_record} orphans={orphan_count}");
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("controller factory still shared")?
        .stop()?;
    drop(fixture.loopback);
    check_final_process_failures(None)?;
    if let Some(error) = failure {
        return Err(error);
    }
    if !sdk
        || completion != Some(!lose_parent)
        || !blocked
        || !wiped
        || !failed
        || !no_resurrection
        || !plan_wiped
        || !idle
        || !no_record
        || (lose_parent && !expected_orphan)
        || (!lose_parent && !matched_exit)
    {
        return Err("actual controller input outcome or ownership was not established".into());
    }
    Ok(())
}

impl crate::Native {
    pub(crate) fn native_controller_failure_from_owned_parent_loss() -> TestResult {
        let _port = Self::fixed_port_fixture();
        let root = FixtureRoot::new()?;
        let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
            .ok_or("canonical retained runtime is required by process qualification")?;
        run_controller_input_case(Path::new(&runtime), &root.0, 0xd0, false)?;
        run_controller_input_case(Path::new(&runtime), &root.0, 0xd1, true)?;
        fresh_success_after_retirement(Path::new(&runtime), &root.0, 0xd4)
    }
}

struct PendingControllerEvidence {
    active_blocked: bool,
    abandoned_blocked: bool,
    no_resurrection: bool,
    browser: Option<pos_owner_bridge::ProcessIdentity>,
}

impl Fixture {
    fn drive_outstanding_controller(
        &mut self,
        driver: &mut CeremonyDriver,
        ceremony: &CeremonyId,
    ) -> Result<(CeremonyResult, PendingControllerEvidence), Box<dyn std::error::Error>> {
        use crate::adapter::surface::PreEnvironmentRetention::{Abandoned, Active};

        loop {
            let step = driver.step(&mut readiness::env(
                &mut self.surface,
                &mut self.loopback,
                &mut self.store,
            ));
            if matches!(&step, Step::Pending) && self.surface.recordless_opening_ready() {
                break;
            }
            match step {
                Step::Finished(_) | Step::Done => {
                    return Err("controller did not remain pending".into())
                }
                Step::Pending => readiness::pump(&self.surface)?,
            }
        }
        let active_blocked = self.surface.controller_creation_retention(ceremony) == Some(Active)
            && matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            && self.surface.controller_creation_retention(ceremony) == Some(Active)
            && crate::Native::callback_order()
                == [crate::NativeCallbackMoment::EnvironmentCompletion(true)];
        let result = readiness::cancel_driver(
            driver,
            &mut self.surface,
            &mut self.loopback,
            &mut self.store,
        );
        self.surface.abandon_opening();
        let mut abandoned_blocked = self.surface.controller_creation_retention(ceremony)
            == Some(Abandoned)
            && matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            && self.surface.controller_creation_retention(ceremony) == Some(Abandoned)
            && crate::Native::callback_order()
                == [crate::NativeCallbackMoment::EnvironmentCompletion(true)];
        let no_resurrection = self.finished_driver_is_done(driver);
        loop {
            match self.surface.pending_opening_completion() {
                Some(true) => break,
                Some(false) => return Err("late controller callback was a native failure".into()),
                None if Instant::now() >= self.deadline => {
                    return Err("late controller callback was not observed".into())
                }
                None => readiness::pump(&self.surface)?,
            }
        }
        let browser = self.surface.abandoned_completed_browser(ceremony).ok();
        let no_resurrection = no_resurrection && self.finished_driver_is_done(driver);
        abandoned_blocked &= browser.is_some()
            && self.surface.recordless_fault_owners_retained()
            && matches!(self.surface.open(&competing_spec()), Poll::Ready(Err(_)))
            && self.surface.recordless_fault_owners_retained();
        Ok((
            result,
            PendingControllerEvidence {
                active_blocked,
                abandoned_blocked,
                no_resurrection,
                browser,
            },
        ))
    }
}

#[test]
fn native_outstanding_controller_callback_survives_abandonment() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let runtime = std::env::var_os("OWNER_BRIDGE_TEST_RUNTIME")
        .ok_or("canonical retained runtime is required by process qualification")?;
    let callback_guard = CallbackOrderGuard::arm();
    let creation_guard = CreationOrderGuard::arm();
    crate::Native::reset_process_failure_observations();
    let number = 0xd2;
    let ceremony = CeremonyId::from_bytes([number; 16]);
    let mut fixture = Fixture::new(
        Path::new(&runtime),
        &root.0,
        number,
        FixtureProfile::Pending,
    )?;
    let mut driver = readiness::new_driver(ceremony, Instant::now())?;
    let mut evidence = None;
    let attempt = catch_unwind(AssertUnwindSafe(|| {
        fixture
            .drive_outstanding_controller(&mut driver, &ceremony)
            .map(|(result, observed)| {
                evidence = Some(observed);
                result
            })
    }));
    let (result, failure) = fixture.resolve_attempt(&mut driver, attempt);
    let failed = result.is_err();
    let wiped = driver.request_clear() && driver.prf().iter().all(|byte| *byte == 0);
    let plan_wiped =
        !matches!(&result, Err(BridgeError::Quarantine(_))) || driver.plan_secrets_clear();
    fixture.surface.abandon_opening();
    retirement::retire(
        &mut fixture.surface,
        &mut fixture.loopback,
        &mut fixture.store,
        driver,
        result,
        |_, _, _| {},
    );
    let actual_exit = fixture.surface.recordless_fault_event().ok().flatten();
    let order = crate::Native::creation_order();
    let callbacks = crate::Native::callback_order();
    let idle = fixture.surface.idle();
    let no_record = fixture.store.records()?.is_empty();
    let no_orphan = fixture.store.folders()?.is_empty();
    let matched = evidence
        .as_ref()
        .and_then(|proof| proof.browser)
        .is_some_and(|browser| {
            callbacks
                == [
                    crate::NativeCallbackMoment::EnvironmentCompletion(true),
                    crate::NativeCallbackMoment::ControllerCompletion(true),
                    crate::NativeCallbackMoment::BrowserExit(browser.browser_pid),
                ]
                && actual_exit == Some(ProcessFaultMark::OwnBrowserExited)
        });
    let _logged = writeln!(std::io::stderr(), "NATIVE_OUTSTANDING_CONTROLLER evidence={} matched={matched} failed={failed} wiped={wiped} idle={idle} no_record={no_record} no_orphan={no_orphan} order={order:?} callbacks={callbacks:?}", evidence.is_some());
    drop(fixture.surface);
    Rc::get_mut(&mut fixture.factory)
        .ok_or("late-controller factory still shared")?
        .stop()?;
    drop(fixture.loopback);
    // The retired fixture still owns the records directory handle; release it
    // before the later fresh ceremony and final root removal on Windows.
    drop(fixture.store);
    check_final_process_failures(None)?;
    if let Some(error) = failure {
        return Err(error);
    }
    let proof = evidence.ok_or("pending controller evidence missing")?;
    if !proof.active_blocked
        || !proof.abandoned_blocked
        || !proof.no_resurrection
        || !matched
        || !failed
        || !wiped
        || !plan_wiped
        || !idle
        || !no_record
        || !no_orphan
        || !sdk_controller_result(&order, crate::CreationCallback::Success)
    {
        return Err(
            "actual outstanding controller callback or retirement was not established".into(),
        );
    }
    drop(callback_guard);
    drop(creation_guard);
    fresh_success_after_retirement(Path::new(&runtime), &root.0, 0xd3)?;
    root.remove()
        .map_err(|error| format!("late-controller fixture root removal: {error}").into())
}
