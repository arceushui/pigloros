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
        assert!(!fixture.factory.calls.borrow().contains(&"navigate"));
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
