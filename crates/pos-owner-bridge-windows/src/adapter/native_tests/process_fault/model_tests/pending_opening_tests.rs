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
    let driver = readiness::new_driver(id, Instant::now())?;
    fixture.retire(driver, Err(ERROR), Some(id))?;
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
        let result =
            fixture.observe_pending_opening_with_observations(BROWSER, FIRST, &clock, || {
                reads.set(reads.get() + 1);
                Vec::new()
            });
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
        let result =
            fixture.observe_pending_opening_with_observations(BROWSER, FIRST, &clock, || order);
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
    let result = fixture.observe_pending_opening_with_observations(other, FIRST, &clock, Vec::new);
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
        let result =
            fixture.observe_pending_opening_with_observations(BROWSER, FIRST, &clock, Vec::new);
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
fn modeled_pending_observer_entry_requires_the_real_callback_ledger() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    assert!(crate::Native::callback_order().is_empty());
    let root = FixtureRoot::new()?;
    let (mut fixture, model, _clock) = pending(&root)?;
    exit(&model)?;
    model.failure.set(Some("pending-callback-after"));
    let result = fixture.observe_pending_opening(BROWSER, FIRST);
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("controller completion was not invoked after the matching exit")
    );
    assert!(!fixture.evidence_complete);
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
        let result =
            fixture.observe_pending_opening_with_observations(BROWSER, FIRST, &clock, || {
                if !slow_exit {
                    callback_clock.advance(Duration::from_secs(6));
                }
                vec![
                    NativeCallbackMoment::BrowserExit(42),
                    NativeCallbackMoment::ControllerCompletion(true),
                ]
            });
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
