#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::fake::host::StoreOp;
use pos_owner_bridge::{
    BridgeError, LifecycleCode, NavigationId, OwnerWebSurface, PostGuard, ProtocolCode, ReplyImage,
    RequestImage, SurfaceEvent, UnavailableCode,
};
use pos_owner_bridge_codec::{CeremonyId, CeremonyKind, OwnerBridgeControlV1};

use super::{Creation, Fixture, TestResult};

fn pair() -> Result<(RequestImage, [u8; 64]), Box<dyn std::error::Error>> {
    let id = CeremonyId::from_bytes([1; 16]);
    let request_header = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, id, 1)
        .map_err(|error| error.to_string())?
        .encode();
    let reply_header = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, id)
        .map_err(|error| error.to_string())?
        .encode();
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes()[..64].copy_from_slice(&request_header);
    Ok((request, reply_header))
}

const fn guard() -> PostGuard {
    PostGuard {
        generation: 1,
        navigation_id: NavigationId(7),
        served_count: 1,
    }
}

const fn unavailable() -> BridgeError {
    BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable)
}

fn posts(fixture: &Fixture) -> Vec<&'static str> {
    fixture
        .factory
        .calls
        .borrow()
        .iter()
        .copied()
        .filter(|call| matches!(*call, "post_request" | "post_reply"))
        .collect()
}

#[test]
fn post_rechecks_the_current_document_between_native_calls() -> TestResult {
    for (failure, invalidated, expected) in [
        (None, false, vec!["post_request", "post_reply"]),
        (Some("post_request"), false, vec!["post_request"]),
        (
            Some("post_reply"),
            false,
            vec!["post_request", "post_reply"],
        ),
        (None, true, vec!["post_request"]),
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        let (request, header) = pair()?;
        fixture
            .surface
            .create_and_write(&request, &header)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        fixture.factory.failure.set(failure);
        fixture.factory.invalidate_request.set(invalidated);
        let result = fixture.surface.post(&guard());
        assert_eq!(result.is_ok(), failure.is_none() && !invalidated);
        if invalidated {
            assert_eq!(
                result.map_err(pos_owner_bridge::SurfaceError::error),
                Err(BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
            );
        } else if failure.is_some() {
            assert_eq!(
                result.map_err(pos_owner_bridge::SurfaceError::error),
                Err(unavailable())
            );
        }
        assert_eq!(posts(&fixture), expected);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn post_requires_a_single_integrity_checked_current_document() -> TestResult {
    for (count, integrity, expected) in [
        (
            0,
            true,
            BridgeError::Unavailable(UnavailableCode::AssetIntegrity),
        ),
        (
            1,
            false,
            BridgeError::Unavailable(UnavailableCode::AssetIntegrity),
        ),
        (
            2,
            true,
            BridgeError::Protocol(ProtocolCode::DuplicateDocumentLoad),
        ),
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        let (request, header) = pair()?;
        fixture
            .surface
            .create_and_write(&request, &header)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        fixture.loopback.set_served(count, integrity);
        assert_eq!(
            fixture
                .surface
                .post(&guard())
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(expected)
        );
        assert!(posts(&fixture).is_empty());
        fixture.finish()?;
    }
    for invalid_guard in [
        PostGuard {
            generation: 2,
            ..guard()
        },
        PostGuard {
            navigation_id: NavigationId(8),
            ..guard()
        },
        PostGuard {
            served_count: 0,
            ..guard()
        },
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        let (request, header) = pair()?;
        fixture
            .surface
            .create_and_write(&request, &header)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert_eq!(
            fixture
                .surface
                .post(&invalid_guard)
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
        );
        assert!(posts(&fixture).is_empty());
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn current_source_is_read_again_before_a_pair_is_posted() -> TestResult {
    for failure in [None, Some("source")] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        let (request, header) = pair()?;
        fixture
            .surface
            .create_and_write(&request, &header)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        *fixture.factory.source.borrow_mut() = "https://example.invalid/".to_owned();
        fixture.factory.failure.set(failure);
        let expected = if failure.is_some() {
            unavailable()
        } else {
            BridgeError::Lifecycle(LifecycleCode::NavigationViolation)
        };
        assert_eq!(
            fixture
                .surface
                .post(&guard())
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(expected)
        );
        assert!(posts(&fixture).is_empty());
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn malformed_or_mismatched_headers_never_create_a_mapping() -> TestResult {
    // Header byte offsets are independent codec fixtures: role8, kind9,
    // generation12, ceremony16, capacity32, state40, flags44.
    for (request_side, offset, value) in [
        (true, 0, 0),
        (false, 0, 0),
        (true, 8, 1),
        (false, 8, 0),
        (true, 40, 0),
        (false, 40, 2),
        (false, 12, 2),
        (false, 9, 1),
        (false, 16, 2),
        (true, 32, 1),
        (false, 44, 1),
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        let (mut request, mut header) = pair()?;
        if request_side {
            request.as_mut_bytes()[offset] = value;
        } else {
            header[offset] = value;
        }
        assert!(fixture.surface.create_and_write(&request, &header).is_err());
        assert!(!fixture.factory.calls.borrow().contains(&"create_buffers"));
        fixture.finish()?;
    }
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    let (request, header) = pair()?;
    fixture.factory.failure.set(Some("create_buffers"));
    assert_eq!(
        fixture
            .surface
            .create_and_write(&request, &header)
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(unavailable())
    );
    fixture.factory.failure.set(None);
    fixture
        .surface
        .create_and_write(&request, &header)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.create_and_write(&request, &header).is_err());
    fixture.finish()?;
    Ok(())
}

#[test]
fn buffer_operations_map_native_errors_and_preserve_observed_results() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    let (request, header) = pair()?;
    fixture
        .surface
        .create_and_write(&request, &header)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(
        fixture
            .surface
            .reply_load_state()
            .map_err(pos_owner_bridge::SurfaceError::error)?,
        0
    );
    assert!(fixture
        .surface
        .reply_compare_exchange(0, 4)
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    assert!(!fixture
        .surface
        .reply_compare_exchange(0, 2)
        .map_err(pos_owner_bridge::SurfaceError::error)?);
    let mut copy = ReplyImage::zeroed();
    fixture
        .surface
        .reply_copy(&mut copy)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(copy.as_bytes().iter().all(|byte| *byte == 0x5a));
    fixture.factory.failure.set(Some("load_state"));
    assert_eq!(
        fixture
            .surface
            .reply_load_state()
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(unavailable())
    );
    fixture.factory.failure.set(Some("compare_exchange"));
    assert_eq!(
        fixture
            .surface
            .reply_compare_exchange(4, 5)
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(unavailable())
    );
    fixture.factory.failure.set(Some("copy_reply"));
    assert_eq!(
        fixture
            .surface
            .reply_copy(&mut copy)
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(unavailable())
    );
    fixture.finish()?;
    Ok(())
}

#[test]
fn cleanup_attempts_controller_close_after_buffer_and_subscription_errors() -> TestResult {
    for failure in ["close_buffers", "unsubscribe_view", "close_controller"] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        fixture.factory.failure.set(Some(failure));
        assert_eq!(
            fixture
                .surface
                .close_controller()
                .map_err(pos_owner_bridge::SurfaceError::error),
            Err(unavailable())
        );
        let calls = fixture.factory.calls.borrow();
        assert_eq!(
            &calls[calls.len() - 3..],
            &["close_buffers", "unsubscribe_view", "close_controller"]
        );
        drop(calls);
        fixture.finish()?;
    }
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    fixture.factory.close_uncertain.set(true);
    assert_eq!(
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(unavailable())
    );
    fixture.finish()?;
    Ok(())
}

#[test]
fn window_changes_are_observed_before_a_post_and_loss_is_emitted_once() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    // Consume the real adapter's DOM notification before inspecting loss.
    assert_eq!(
        fixture.surface.take_event(),
        Some(SurfaceEvent::DomContentLoaded(NavigationId(7)))
    );
    fixture.factory.calls.borrow_mut().clear();
    fixture.factory.dpi.set(144);
    assert_eq!(fixture.surface.take_event(), None);
    assert_eq!(
        &*fixture.factory.calls.borrow(),
        &["resize_window", "fit_controller"]
    );
    fixture.factory.calls.borrow_mut().clear();
    fixture.factory.client.set(crate::ClientBounds {
        left: 0,
        top: 0,
        right: 720,
        bottom: 960,
    });
    assert_eq!(fixture.surface.take_event(), None);
    assert_eq!(&*fixture.factory.calls.borrow(), &["fit_controller"]);
    fixture.factory.close_requested.set(true);
    assert_eq!(
        fixture.surface.take_event(),
        Some(SurfaceEvent::ControllerLost)
    );
    assert_eq!(fixture.surface.take_event(), None);
    fixture.finish()?;
    Ok(())
}

#[test]
fn a_navigation_start_without_dom_completion_does_not_authorize_a_post() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.navigation_succeeds.set(true);
    fixture
        .open(&super::spec(41))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.navigate().is_pending());
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(crate::NativeEvent::Navigation {
        uri: crate::NativeText::fixture(crate::OWNER_URL),
        id: 7,
        redirected: false,
    });
    fixture.loopback.set_served(1, true);
    let (request, header) = pair()?;
    fixture
        .surface
        .create_and_write(&request, &header)
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(
        fixture
            .surface
            .post(&guard())
            .map_err(pos_owner_bridge::SurfaceError::error),
        Err(BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
    );
    assert!(posts(&fixture).is_empty());
    fixture.finish()?;
    Ok(())
}

#[test]
fn failed_native_preparation_returns_identity_before_refusing_navigation() -> TestResult {
    for failure in [
        "require_shared_interfaces",
        "subscribe_view",
        "set_bool",
        "get_bool",
        "fit_controller",
        "show_window",
        "focus_controller",
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.failure.set(Some(failure));
        let identity = fixture
            .open(&super::spec(42))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert_eq!(identity.browser_pid, 42);
        assert!(matches!(
            fixture.surface.navigate(),
            std::task::Poll::Ready(Err(_))
        ));
        let attempts = fixture
            .factory
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == failure)
            .count();
        assert!(matches!(
            fixture.surface.navigate(),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(
            fixture
                .factory
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == failure)
                .count(),
            attempts
        );
        assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn timely_foreground_survives_slow_focus_when_still_foreground() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture
        .factory
        .focus_delay
        .set(std::time::Duration::from_millis(1_100));
    fixture.factory.navigation_succeeds.set(true);
    fixture
        .open(&super::spec(130))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.navigate().is_pending());
    assert!(fixture.surface.navigate().is_pending());
    let calls = fixture.factory.calls.borrow();
    let activation: Vec<_> = calls
        .iter()
        .filter(|call| matches!(**call, "show_window" | "focus_controller" | "navigate"))
        .copied()
        .collect();
    assert_eq!(activation, ["show_window", "focus_controller", "navigate"]);
    drop(calls);
    fixture.finish()?;
    Ok(())
}

#[test]
fn foreground_observation_is_optional_and_never_extends_deadlines() -> TestResult {
    use pos_owner_bridge::MonotonicClock as _;
    use std::time::Duration;

    for case in [
        "query_error",
        "boundary",
        "crossing",
        "lost",
        "late_first",
        "readiness",
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.navigation_succeeds.set(true);
        fixture
            .open(&super::spec(131))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        match case {
            "query_error" => fixture.factory.pre_focus_window_error.set(true),
            "boundary" => fixture.factory.show_delay.set(Duration::from_secs(1)),
            "crossing" => fixture
                .factory
                .pre_focus_window_delay
                .set(Duration::from_secs(1)),
            "lost" => {
                fixture.factory.focus_foreground.set(Some(false));
                fixture
                    .factory
                    .focus_delay
                    .set(Duration::from_millis(1_100));
            }
            "late_first" => {
                fixture.factory.foreground.set(false);
                fixture.factory.focus_foreground.set(Some(true));
                fixture
                    .factory
                    .focus_delay
                    .set(Duration::from_millis(1_100));
            }
            "readiness" => {
                fixture
                    .surface
                    .set_deadline(fixture.clock.now() + Duration::from_millis(500));
                fixture.factory.focus_delay.set(Duration::from_millis(500));
            }
            _ => return Err("unknown foreground observation case".into()),
        }
        let result = fixture.surface.navigate();
        if case == "query_error" {
            assert!(result.is_pending(), "{case}");
            assert!(fixture.factory.calls.borrow().contains(&"navigate"));
        } else {
            let expected = if case == "readiness" {
                LifecycleCode::ReadinessTimeout
            } else {
                LifecycleCode::ForegroundUnavailable
            };
            assert!(
                matches!(result, std::task::Poll::Ready(Err(error)) if error.error() == BridgeError::Lifecycle(expected)),
                "{case}"
            );
            fixture.assert_no_ceremony_data();
            assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
        }
        assert_eq!(
            fixture
                .factory
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == "focus_controller")
                .count(),
            1,
            "{case}"
        );
        fixture.factory.pre_focus_window_error.set(false);
        fixture.factory.pre_focus_window_delay.set(Duration::ZERO);
        fixture.factory.show_delay.set(Duration::ZERO);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn foreground_lost_during_focus_must_be_reacquired_before_original_deadline() -> TestResult {
    use std::time::Duration;

    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.navigation_succeeds.set(true);
    fixture.factory.focus_foreground.set(Some(false));
    fixture
        .open(&super::spec(132))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.navigate().is_pending());
    assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
    fixture.clock.advance(Duration::from_millis(999));
    fixture.factory.foreground.set(true);
    assert!(fixture.surface.navigate().is_pending());
    let calls = fixture.factory.calls.borrow();
    let activation: Vec<_> = calls
        .iter()
        .filter(|call| matches!(**call, "show_window" | "focus_controller" | "navigate"))
        .copied()
        .collect();
    assert_eq!(activation, ["show_window", "focus_controller", "navigate"]);
    drop(calls);
    fixture.finish()?;
    Ok(())
}

#[test]
fn foreground_activation_waits_for_navigation_after_slow_record_work() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.navigation_succeeds.set(true);
    let identity = fixture
        .open(&super::spec(126))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert_eq!(identity.browser_pid, 42);
    for forbidden in [
        "show_window",
        "focus_controller",
        "navigate",
        "create_buffers",
        "post_request",
        "post_reply",
    ] {
        assert!(
            !fixture.factory.calls.borrow().contains(&forbidden),
            "{forbidden}"
        );
    }
    fixture
        .clock
        .advance(std::time::Duration::from_millis(1_400));
    assert!(fixture.surface.navigate().is_pending());
    assert!(fixture.surface.navigate().is_pending());
    let calls = fixture.factory.calls.borrow();
    let positions: Vec<_> = calls
        .iter()
        .filter(|call| matches!(**call, "show_window" | "focus_controller" | "navigate"))
        .copied()
        .collect();
    assert_eq!(positions, ["show_window", "focus_controller", "navigate"]);
    drop(calls);
    fixture.finish()?;
    Ok(())
}

struct DelayedRecord<'a> {
    store: &'a mut pos_owner_bridge::fake::host::FakeStore,
    clock: &'a pos_owner_bridge::fake::clock::FakeClock,
    factory: &'a super::native::Factory,
}

impl pos_owner_bridge::CleanupStore for DelayedRecord<'_> {
    fn write_record(&mut self, record: &[u8]) -> Result<(), pos_owner_bridge::CleanupError> {
        for operation in [
            "show_window",
            "focus_controller",
            "navigate",
            "create_buffers",
        ] {
            assert!(
                !self.factory.calls.borrow().contains(&operation),
                "{operation}"
            );
        }
        let result = self.store.write_record(record);
        self.clock.advance(std::time::Duration::from_millis(1_400));
        result
    }
    fn delete_record(&mut self, record: &[u8]) -> Result<(), pos_owner_bridge::CleanupError> {
        self.store.delete_record(record)
    }
    fn records(&mut self) -> Result<Vec<Vec<u8>>, pos_owner_bridge::CleanupError> {
        self.store.records()
    }
    fn folders(&mut self) -> Result<Vec<String>, pos_owner_bridge::CleanupError> {
        self.store.folders()
    }
    fn remove_folder(&mut self, name: &str) -> Result<(), pos_owner_bridge::CleanupError> {
        self.store.remove_folder(name)
    }
}

#[test]
fn driver_persists_and_probes_before_one_time_activation() -> TestResult {
    for (case, expected) in [
        (
            "success",
            &["show_window", "focus_controller", "navigate"][..],
        ),
        ("record", &[][..]),
        ("probe", &[][..]),
        ("show_window", &["show_window"][..]),
        ("focus_controller", &["show_window", "focus_controller"][..]),
    ] {
        run_driver_activation_case(case, expected)?;
    }
    Ok(())
}

fn run_driver_activation_case(case: &'static str, expected: &[&str]) -> TestResult {
    use pos_owner_bridge::ceremony::driver::{CeremonyDriver, Step, StepEnv};
    use pos_owner_bridge::ceremony::plan::CeremonyPlan;
    use pos_owner_bridge::MonotonicClock as _;
    use pos_owner_bridge_codec::{OwnerUserHandle, PrfInput, WebAuthnChallenge};

    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.navigation_succeeds.set(true);
    if case == "record" {
        fixture.store.set_failing(&[StoreOp::Write]);
    } else if case == "probe" {
        fixture.loopback.fail_probes_from(Some(1));
    } else if matches!(case, "show_window" | "focus_controller") {
        fixture.factory.failure.set(Some(case));
    }
    let mut storage = fixture.store.clone();
    let mut loopback = fixture.loopback.clone();
    let mut store = DelayedRecord {
        store: &mut storage,
        clock: &fixture.clock,
        factory: &fixture.factory,
    };
    let plan = CeremonyPlan::for_test(
        CeremonyKind::Create,
        CeremonyId::from_bytes([128; 16]),
        WebAuthnChallenge::from_bytes([2; 32]),
        OwnerUserHandle::from_bytes([3; 32]),
        PrfInput::from_bytes([4; 32]),
        fixture.clock.now(),
    );
    let mut driver = CeremonyDriver::for_test(plan);
    for _ in 0..8 {
        let mut env = StepEnv {
            surface: &mut fixture.surface,
            clock: &fixture.clock,
            loopback: &mut loopback,
            store: &mut store,
        };
        assert!(matches!(driver.step(&mut env), Step::Pending), "{case}");
        let calls = fixture.factory.calls.borrow();
        let progressed = calls.contains(&"navigate") || calls.contains(&"close_controller");
        drop(calls);
        if progressed {
            break;
        }
        fixture
            .surface
            .pump()
            .map_err(|error| format!("pump: {error:?}"))?;
    }
    let calls = fixture.factory.calls.borrow();
    let activation: Vec<_> = calls
        .iter()
        .filter(|call| matches!(**call, "show_window" | "focus_controller" | "navigate"))
        .copied()
        .collect();
    assert_eq!(activation, expected, "{case}");
    drop(calls);
    assert_eq!(
        fixture.store.records_now().len(),
        usize::from(case != "record"),
        "{case}"
    );
    assert_eq!(
        fixture.loopback.probes(),
        u32::from(case != "record"),
        "{case}"
    );
    fixture.factory.failure.set(None);
    if case == "success" {
        fixture
            .factory
            .sink
            .borrow()
            .as_ref()
            .ok_or("missing sink")?
            .event(crate::NativeEvent::ProcessFailed);
        let mut env = StepEnv {
            surface: &mut fixture.surface,
            clock: &fixture.clock,
            loopback: &mut loopback,
            store: &mut store,
        };
        assert!(matches!(driver.step(&mut env), Step::Pending));
    }
    fixture.exit();
    let mut env = StepEnv {
        surface: &mut fixture.surface,
        clock: &fixture.clock,
        loopback: &mut loopback,
        store: &mut store,
    };
    assert!(
        matches!(driver.step(&mut env), Step::Finished(Err(_))),
        "{case}"
    );
    assert!(fixture.surface.idle());
    assert!(fixture.store.records_now().is_empty());
    Ok(())
}

#[test]
fn reentrant_denial_during_activation_prevents_navigation() -> TestResult {
    for operation in ["show_window", "window", "focus_controller"] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.reenter_on_activation.set(Some(operation));
        fixture.factory.navigation_succeeds.set(true);
        fixture
            .open(&super::spec(127))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        for _ in 0..2 {
            assert!(
                matches!(fixture.surface.navigate(), std::task::Poll::Ready(Err(error))
                if error.error() == BridgeError::Lifecycle(LifecycleCode::NavigationViolation))
            );
        }
        let calls = fixture.factory.calls.borrow();
        let activation: Vec<_> = calls
            .iter()
            .filter(|call| matches!(**call, "show_window" | "focus_controller" | "navigate"))
            .copied()
            .collect();
        assert_eq!(activation, ["show_window", "focus_controller"]);
        drop(calls);
        fixture.assert_no_ceremony_data();
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn foreground_deadline_refuses_navigation_and_preserves_ownership() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.factory.foreground.set(false);
    fixture.factory.navigation_succeeds.set(true);
    fixture
        .open(&super::spec(122))
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.navigate().is_pending());
    fixture.clock.advance(std::time::Duration::from_millis(999));
    assert!(fixture.surface.navigate().is_pending());
    fixture.clock.advance(std::time::Duration::from_millis(1));
    assert!(
        matches!(fixture.surface.navigate(), std::task::Poll::Ready(Err(error))
        if error.error() == BridgeError::Lifecycle(LifecycleCode::ForegroundUnavailable))
    );
    assert!(matches!(
        fixture.surface.open(&super::spec(123)),
        std::task::Poll::Ready(Err(_))
    ));
    fixture.assert_no_ceremony_data();
    assert!(!fixture.surface.idle());
    fixture.finish()?;
    Ok(())
}

#[test]
fn incorrect_successful_setting_readback_refuses_navigation() -> TestResult {
    for property in [crate::BoolProperty::Script, crate::BoolProperty::WebMessage] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.mismatched_setting.set(Some(property));
        let identity = fixture
            .open(&super::spec(124))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert_eq!(identity.browser_pid, 42);
        assert!(
            matches!(fixture.surface.navigate(), std::task::Poll::Ready(Err(error))
            if error.error() == unavailable())
        );
        assert!(matches!(
            fixture.surface.open(&super::spec(125)),
            std::task::Poll::Ready(Err(_))
        ));
        fixture.assert_no_ceremony_data();
        assert!(!fixture.surface.idle());
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn finish_requires_matching_exit_and_retries_each_failed_cleanup_effect() -> TestResult {
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    assert!(fixture.surface.finish().is_err());
    let sink = fixture
        .factory
        .sink
        .borrow()
        .clone()
        .ok_or("missing sink")?;
    sink.event(crate::NativeEvent::BrowserExited { pid: 99 });
    assert!(fixture.surface.finish().is_err());
    assert!(fixture.store.removed_folders().is_empty());
    fixture.finish()?;
    for failure in [
        "unsubscribe_view",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.ready()?;
        fixture
            .surface
            .close_controller()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        fixture.exit();
        fixture.factory.failure.set(Some(failure));
        assert!(fixture.surface.finish().is_err());
        assert!(!fixture.surface.idle());
        assert!(fixture.store.removed_folders().is_empty());
        fixture.factory.failure.set(None);
        fixture
            .surface
            .finish()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!(fixture.surface.idle());
    }
    let mut fixture = Fixture::new(Creation::Ready)?;
    fixture.ready()?;
    fixture
        .surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    fixture.exit();
    fixture.store.set_failing(&[StoreOp::Remove]);
    assert!(fixture.surface.finish().is_err());
    assert!(!fixture.surface.idle());
    fixture.store.set_failing(&[]);
    fixture
        .surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    assert!(fixture.surface.idle());
    Ok(())
}

#[test]
fn foreground_budget_bounds_show_and_each_first_observation() -> TestResult {
    use std::time::Duration;

    for case in [
        "late_true",
        "boundary",
        "show",
        "query",
        "readiness",
        "on_time",
    ] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture.factory.navigation_succeeds.set(true);
        if case == "show" {
            fixture.factory.show_delay.set(Duration::from_secs(1));
        }
        if matches!(case, "late_true" | "boundary") {
            fixture.factory.foreground.set(false);
        }
        fixture
            .open(&super::spec(125))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        match case {
            "late_true" => {
                assert!(fixture.surface.navigate().is_pending());
                fixture.clock.advance(Duration::from_millis(1001));
                fixture.factory.foreground.set(true);
            }
            "boundary" => {
                assert!(fixture.surface.navigate().is_pending());
                fixture.clock.advance(Duration::from_secs(1));
            }
            "readiness" => fixture.clock.advance(Duration::from_secs(30)),
            "query" => fixture.factory.window_delay.set(Duration::from_secs(1)),
            _ => {}
        }
        let result = fixture.surface.navigate();
        if case == "on_time" {
            assert!(result.is_pending());
            fixture.clock.advance(Duration::from_secs(2));
            assert!(fixture.surface.navigate().is_pending());
            assert_eq!(
                fixture
                    .factory
                    .calls
                    .borrow()
                    .iter()
                    .filter(|call| **call == "navigate")
                    .count(),
                1
            );
        } else {
            let expected = if case == "readiness" {
                LifecycleCode::ReadinessTimeout
            } else {
                LifecycleCode::ForegroundUnavailable
            };
            assert!(
                matches!(result, std::task::Poll::Ready(Err(error))
                if error.error() == BridgeError::Lifecycle(expected)),
                "{case}"
            );
            fixture.assert_no_ceremony_data();
            assert!(!fixture.surface.idle());
        }
        fixture.factory.window_delay.set(Duration::ZERO);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn readiness_deadline_crossed_during_foreground_operations_blocks_navigation() -> TestResult {
    use pos_owner_bridge::MonotonicClock as _;
    use std::time::Duration;

    for operation in ["show", "window"] {
        let mut fixture = Fixture::new(Creation::Ready)?;
        fixture
            .open(&super::spec(126))
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let remaining = Duration::from_millis(500);
        let deadline = fixture.clock.now() + remaining;
        fixture.surface.set_deadline(deadline);
        if operation == "show" {
            fixture.factory.show_delay.set(remaining);
        } else {
            fixture.factory.window_delay.set(Duration::from_millis(300));
        }
        assert!(matches!(
            fixture.surface.navigate(),
            std::task::Poll::Ready(Err(error))
                if error.error() == BridgeError::Lifecycle(LifecycleCode::ReadinessTimeout)
        ));
        let expected = if operation == "show" {
            deadline
        } else {
            deadline + Duration::from_millis(100)
        };
        assert_eq!(fixture.clock.now(), expected);
        assert!(fixture.factory.calls.borrow().contains(&"show_window"));
        fixture.assert_no_ceremony_data();
        assert!(!fixture.surface.idle());
        fixture.factory.window_delay.set(Duration::ZERO);
        fixture.factory.show_delay.set(Duration::ZERO);
        fixture.finish()?;
    }
    Ok(())
}
