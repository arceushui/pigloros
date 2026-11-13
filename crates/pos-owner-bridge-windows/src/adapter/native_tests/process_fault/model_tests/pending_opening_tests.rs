#![cfg(windows)]
#![forbid(unsafe_code)]

//! Scripted observations exercise the pending-opening harness observer.

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{MonotonicClock, OwnerWebSurface, ProcessIdentity};
use pos_owner_bridge_codec::{CeremonyId, ImagePathSha256};

use super::{fixture, readiness, Handle, TickingClock, ERROR, MODEL_CASE};
use crate::adapter::native_tests::process_fault::{Fixture, FixtureRoot, TestResult};
use crate::adapter::surface::tests::native::{Creation, Factory};
use crate::{NativeCallbackMoment, NativeEvent, ProcessFaultHandle, ProcessFaultMark};

const BROWSER: ProcessIdentity = ProcessIdentity {
    browser_pid: 42,
    creation_filetime: 1,
    image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
};
const FIRST: ProcessFaultMark = ProcessFaultMark::PendingOpening {
    generation: 1,
    record_count: 0,
};

fn pending(
    root: &FixtureRoot,
) -> Result<(Fixture, Rc<Factory>, TickingClock), Box<dyn std::error::Error>> {
    let (mut fixture, model) = fixture(root)?;
    model.creation.set(Creation::Pending);
    let selected = super::super::fixed_competing_spec(MODEL_CASE);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    model.pending_browser.set(Some(BROWSER));
    assert_eq!(
        fixture.surface.prepare_pending_opening_browser(),
        Ok(Some(BROWSER))
    );
    let clock = TickingClock(FakeClock::start());
    fixture.deadline = clock.now() + Duration::from_secs(5);
    fixture.trace.borrow_mut().extend([
        FIRST,
        ProcessFaultMark::Selected(BROWSER),
        ProcessFaultMark::TerminationCall,
    ]);
    fixture.handle = Some(Box::new(Handle {
        code: Ok(Some(0x535)),
        clock: clock.0.clone(),
        advance: Duration::ZERO,
    }));
    Ok((fixture, model, clock))
}

fn exit(model: &Factory) -> TestResult {
    let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
    let _action = sink.event(NativeEvent::BrowserExited {
        pid: BROWSER.browser_pid,
    });
    Ok(())
}

fn retire(root: FixtureRoot, fixture: Fixture, model: &Factory) -> TestResult {
    model.failure.set(None);
    model.creation.set(Creation::CallbackFailure);
    if fixture.surface.recordless_fault_event() != Ok(Some(ProcessFaultMark::OwnBrowserExited)) {
        exit(model)?;
    }
    let id = CeremonyId::from_bytes([MODEL_CASE; 16]);
    let driver = readiness::new_driver(id, Instant::now());
    fixture.retire(driver, Err(ERROR), Some(id));
    root.remove()
}

#[test]
fn modeled_pending_observer_requires_retained_final_status_before_callback_evidence() -> TestResult
{
    let _port = crate::Native::fixed_port_fixture();
    for (code, expected) in [
        (None, "pending-opening handle disappeared"),
        (Some(Err(())), "pending-opening exit query failed"),
        (Some(Ok(None)), "pending-opening process exit pending"),
        (
            Some(Ok(Some(0))),
            "pending-opening fault evidence is incomplete",
        ),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        exit(&model)?;
        fixture.handle = code.map(|code| {
            Box::new(Handle {
                code,
                clock: clock.0.clone(),
                advance: Duration::ZERO,
            }) as Box<dyn ProcessFaultHandle>
        });
        let reads = Cell::new(0);
        let result = fixture.observe_pending_opening_with_observations(
            BROWSER,
            FIRST,
            &clock,
            Box::new(|| {
                reads.set(reads.get() + 1);
                Vec::new()
            }),
        );
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
        assert_eq!(reads.get(), 0);
        assert!(!fixture.evidence_complete);
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_observer_requires_the_selected_browser_and_ordered_callback() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for order in [
        Vec::new(),
        vec![
            NativeCallbackMoment::ControllerCompletion(true),
            NativeCallbackMoment::BrowserExit(42),
        ],
        vec![
            NativeCallbackMoment::BrowserExit(43),
            NativeCallbackMoment::ControllerCompletion(true),
        ],
        vec![
            NativeCallbackMoment::BrowserExit(42),
            NativeCallbackMoment::BrowserExit(42),
            NativeCallbackMoment::ControllerCompletion(true),
        ],
        vec![
            NativeCallbackMoment::BrowserExit(42),
            NativeCallbackMoment::ControllerCompletion(true),
        ],
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        exit(&model)?;
        model.failure.set(Some("pending-callback-after"));
        let expected = order
            == [
                NativeCallbackMoment::BrowserExit(42),
                NativeCallbackMoment::ControllerCompletion(true),
            ];
        let reads = Cell::new(0);
        let result = fixture.observe_pending_opening_with_observations(
            BROWSER,
            FIRST,
            &clock,
            Box::new(|| {
                reads.set(reads.get() + 1);
                order
            }),
        );
        assert_eq!(reads.get(), 1);
        assert_eq!(result.is_ok(), expected);
        assert_eq!(fixture.evidence_complete, expected);
        if expected {
            assert_eq!(
                fixture.trace.borrow().last(),
                Some(&ProcessFaultMark::ControllerCompletion(true))
            );
        } else {
            assert_eq!(
                result.err().map(|error| error.to_string()).as_deref(),
                Some("controller completion was not invoked after the matching exit")
            );
        }
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_observer_rejects_an_exit_handle_for_a_different_browser() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model, clock) = pending(&root)?;
    exit(&model)?;
    let other = ProcessIdentity {
        creation_filetime: 2,
        ..BROWSER
    };
    let result =
        fixture.observe_pending_opening_with_observations(other, FIRST, &clock, Box::new(Vec::new));
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("pending-opening fault evidence is incomplete")
    );
    assert!(!fixture.evidence_complete);
    retire(root, fixture, &model)
}

#[test]
fn modeled_pending_observer_bounds_missing_exit_and_missing_completion() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (exited, expected) in [
        (false, "pending-opening browser exit timed out"),
        (true, "late controller completion was not observed"),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        if exited {
            exit(&model)?;
        }
        let result = fixture.observe_pending_opening_with_observations(
            BROWSER,
            FIRST,
            &clock,
            Box::new(Vec::new),
        );
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
        assert!(!fixture.evidence_complete);
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_observer_requires_the_real_empty_callback_ledger() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    assert!(crate::Native::callback_order().is_empty());
    let root = FixtureRoot::new()?;
    let (mut fixture, model, clock) = pending(&root)?;
    exit(&model)?;
    model.failure.set(Some("pending-callback-after"));
    let result = fixture.observe_pending_opening_with_observations(
        BROWSER,
        FIRST,
        &clock,
        Box::new(crate::Native::callback_order),
    );
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("controller completion was not invoked after the matching exit")
    );
    assert!(!fixture.evidence_complete);
    retire(root, fixture, &model)
}

#[test]
fn modeled_pending_native_entry_refuses_expired_evidence() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model, _clock) = pending(&root)?;
    exit(&model)?;
    model.failure.set(Some("pending-callback-after"));
    fixture.deadline = Instant::now();
    let result = fixture.observe_pending_opening(BROWSER, FIRST);
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("pending-opening browser exit timed out")
    );
    assert!(!fixture.evidence_complete);
    assert_eq!(fixture.trace.borrow().len(), 3);
    retire(root, fixture, &model)
}

#[test]
fn modeled_pending_observer_rejects_evidence_read_after_its_original_deadline() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (slow_exit, expected) in [
        (true, "pending-opening browser exit timed out"),
        (false, "late controller completion was not observed"),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        exit(&model)?;
        model.failure.set(Some("pending-callback-after"));
        if slow_exit {
            fixture.handle = Some(Box::new(Handle {
                code: Ok(Some(0x535)),
                clock: clock.0.clone(),
                advance: Duration::from_secs(6),
            }));
        }
        let callback_clock = clock.0.clone();
        let result = fixture.observe_pending_opening_with_observations(
            BROWSER,
            FIRST,
            &clock,
            Box::new(|| {
                callback_clock.advance(Duration::from_secs(6));
                vec![
                    NativeCallbackMoment::BrowserExit(42),
                    NativeCallbackMoment::ControllerCompletion(true),
                ]
            }),
        );
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some(expected)
        );
        assert!(!fixture.evidence_complete);
        assert!(!matches!(
            fixture.trace.borrow().last(),
            Some(ProcessFaultMark::ControllerCompletion(_))
        ));
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_pending_observer_preserves_pump_failures_before_exit_or_completion() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for exited in [false, true] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        if exited {
            exit(&model)?;
        }
        model.failure.set(Some("pump"));
        let reads = Cell::new(0);
        let result = fixture.observe_pending_opening_with_observations(
            BROWSER,
            FIRST,
            &clock,
            Box::new(|| {
                reads.set(reads.get() + 1);
                Vec::new()
            }),
        );
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some("Sta: CallFailed")
        );
        assert_eq!(reads.get(), 0);
        assert!(!fixture.evidence_complete);
        assert!(fixture.surface.pending_opening_owners_retained());
        assert_eq!(fixture.trace.borrow().len(), if exited { 5 } else { 3 });
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_recordless_observer_enforces_deadline_before_event_and_after_query() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    for (at_boundary, advance, accepted) in [
        (false, Duration::ZERO, true),
        (true, Duration::ZERO, false),
        (false, Duration::from_secs(6), false),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        exit(&model)?;
        fixture.trace.borrow_mut().clear();
        fixture.trace.borrow_mut().extend([
            ProcessFaultMark::RecordlessOpening {
                generation: 1,
                record_count: 0,
            },
            ProcessFaultMark::Selected(BROWSER),
            ProcessFaultMark::TerminationCall,
        ]);
        fixture.handle = Some(Box::new(Handle {
            code: Ok(Some(0x535)),
            clock: clock.0.clone(),
            advance,
        }));
        fixture.deadline = clock.0.now()
            + if at_boundary {
                Duration::ZERO
            } else {
                Duration::from_secs(5)
            };
        let result = fixture.observe_recordless_with_clock(BROWSER, &clock);
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(fixture.evidence_complete, accepted);
        assert_eq!(fixture.trace.borrow().len(), if accepted { 5 } else { 3 });
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_recordless_observer_refuses_untrusted_exit_evidence() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let other_browser = ProcessIdentity {
        creation_filetime: BROWSER.creation_filetime + 1,
        ..BROWSER
    };
    for (label, code, expected_browser, ordered, expected_error) in [
        (
            "missing handle",
            None,
            BROWSER,
            true,
            "recordless handle disappeared",
        ),
        (
            "query failure",
            Some(Err(())),
            BROWSER,
            true,
            "recordless exit query failed",
        ),
        (
            "pending exit",
            Some(Ok(None)),
            BROWSER,
            true,
            "recordless process exit pending",
        ),
        (
            "wrong exit code",
            Some(Ok(Some(0))),
            BROWSER,
            true,
            "recordless fault evidence is incomplete",
        ),
        (
            "wrong browser identity",
            Some(Ok(Some(0x535))),
            other_browser,
            true,
            "recordless fault evidence is incomplete",
        ),
        (
            "wrong trace order",
            Some(Ok(Some(0x535))),
            BROWSER,
            false,
            "recordless fault evidence is incomplete",
        ),
    ] {
        let root = FixtureRoot::new()?;
        let (mut fixture, model, clock) = pending(&root)?;
        exit(&model)?;
        fixture.trace.borrow_mut().clear();
        let opening = ProcessFaultMark::RecordlessOpening {
            generation: 1,
            record_count: 0,
        };
        if ordered {
            fixture.trace.borrow_mut().extend([
                opening,
                ProcessFaultMark::Selected(BROWSER),
                ProcessFaultMark::TerminationCall,
            ]);
        } else {
            fixture.trace.borrow_mut().extend([
                opening,
                ProcessFaultMark::TerminationCall,
                ProcessFaultMark::Selected(BROWSER),
            ]);
        }
        fixture.handle = code.map(|code| {
            Box::new(Handle {
                code,
                clock: clock.0.clone(),
                advance: Duration::ZERO,
            }) as Box<dyn ProcessFaultHandle>
        });
        let result = fixture.observe_recordless_with_clock(expected_browser, &clock);
        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some(expected_error),
            "{label}"
        );
        assert!(!fixture.evidence_complete, "{label}");
        assert!(fixture.surface.pending_opening_owners_retained(), "{label}");
        retire(root, fixture, &model)?;
    }
    Ok(())
}

#[test]
fn modeled_opening_first_refuses_expiry_and_unavailable_fault_authority() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    model.creation.set(Creation::Pending);
    let selected = super::super::fixed_competing_spec(MODEL_CASE);
    assert!(fixture.surface.open(&selected).is_pending());
    assert!(fixture.surface.open(&selected).is_pending());
    model.pending_browser.set(Some(BROWSER));
    fixture.deadline = Instant::now();
    assert_eq!(
        fixture
            .opening_first_browser()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("opening browser cutpoint was not reached")
    );
    assert!(fixture.surface.recordless_opening_ready());
    assert!(!fixture.surface.pending_opening_owners_retained());
    fixture.deadline = Instant::now() + Duration::from_secs(5);
    let (browser, mark) = fixture.opening_first_browser()?;
    assert_eq!(browser, BROWSER);
    assert_eq!(mark, FIRST);
    assert!(!fixture.surface.recordless_opening_ready());
    assert!(fixture.surface.pending_opening_owners_retained());
    assert!(fixture.opening_first_owners_retained(mark));
    assert_eq!(
        fixture
            .inject_opening_first_browser(browser, mark)
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("pending-opening browser fault refused")
    );
    assert!(fixture.handle.is_none());
    assert!(!fixture.evidence_complete);
    assert!(fixture.surface.pending_opening_owners_retained());
    retire(root, fixture, &model)
}

#[test]
fn modeled_opening_first_rejects_an_unrelated_cutpoint() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model, _clock) = pending(&root)?;
    fixture.handle = None;
    let result = fixture.inject_opening_first_browser(BROWSER, ProcessFaultMark::OwnBrowserExited);
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("unexpected opening fault cutpoint")
    );
    assert!(!fixture.opening_first_owners_retained(ProcessFaultMark::OwnBrowserExited));
    assert!(fixture.handle.is_none());
    assert!(!fixture.evidence_complete);
    assert!(fixture.surface.pending_opening_owners_retained());
    retire(root, fixture, &model)
}
