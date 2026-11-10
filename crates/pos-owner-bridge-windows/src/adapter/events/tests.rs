#![cfg(windows)]
#![forbid(unsafe_code)]

use super::*;
use crate::{Failure, NativeText, Operation};

fn text(value: &str) -> NativeText {
    NativeText::fixture(value)
}

fn start(events: &Events, uri: &str, id: u64, redirected: bool) -> NativeAction {
    events.event(NativeEvent::Navigation {
        uri: text(uri),
        id,
        redirected,
    })
}

#[test]
fn permission_diagnostic_navigations_are_closed_and_still_denied() {
    for stage in [
        "denied",
        "default",
        "unexpectedgranted",
        "unexpectedstate",
        "rejected",
        "exception",
        "unavailable",
        "noresult",
        "unknown",
    ] {
        let uri = format!("http://localhost:49291/permission-diag/{stage}");
        assert_eq!(permission_diagnostic(&uri), Some(stage));
        let events = Events::default();
        events.begin();
        assert_eq!(start(&events, OWNER_URL, 1, false), NativeAction::Allow);
        assert_eq!(start(&events, &uri, 2, false), NativeAction::Cancel);
        assert!(events.invalid());
    }
    assert_eq!(
        permission_diagnostic("http://localhost:49291/permission-diag/private"),
        None
    );
}

#[test]
fn exactly_one_initial_navigation_and_matching_document_are_admitted() {
    let events = Events::default();
    events.begin();
    assert_eq!(start(&events, OWNER_URL, 7, false), NativeAction::Allow);
    assert_eq!(events.started(), Some(NavigationId(7)));
    assert_eq!(
        events.event(NativeEvent::Source {
            uri: text(OWNER_URL)
        }),
        NativeAction::Observe
    );
    assert_eq!(
        events.event(NativeEvent::Content {
            id: 7,
            error_page: false
        }),
        NativeAction::Observe
    );
    assert_eq!(
        events.event(NativeEvent::DomLoaded {
            id: 7,
            uri: text(OWNER_URL)
        }),
        NativeAction::Observe
    );
    assert_eq!(events.loaded(), Some(NavigationId(7)));
    assert_eq!(
        events.event(NativeEvent::NavigationCompleted {
            id: 7,
            success: true
        }),
        NativeAction::Observe
    );
    assert!(!events.invalid());
    assert_eq!(
        events.take(),
        Some(SurfaceEvent::DomContentLoaded(NavigationId(7)))
    );
    assert_eq!(events.take(), None);
    events.begin();
    assert_eq!(start(&events, OWNER_URL, 8, false), NativeAction::Cancel);
    assert!(events.invalid());
}

#[test]
fn unsolicited_redirected_and_foreign_navigations_cancel() {
    let events = Events::default();
    assert_eq!(start(&events, OWNER_URL, 1, false), NativeAction::Cancel);
    for (uri, redirected) in [("https://example.invalid", false), (OWNER_URL, true)] {
        let events = Events::default();
        events.begin();
        assert_eq!(start(&events, uri, 1, redirected), NativeAction::Cancel);
        assert!(events.invalid());
    }
}

#[test]
fn document_events_reject_wrong_identity_duplicates_and_error_pages() {
    let events = Events::default();
    events.event(NativeEvent::Source {
        uri: text(OWNER_URL),
    });
    assert!(events.invalid());
    for case in 0..12 {
        let events = Events::default();
        events.begin();
        assert_eq!(start(&events, OWNER_URL, 1, false), NativeAction::Allow);
        match case {
            0 => {
                events.event(NativeEvent::Source {
                    uri: text("about:blank"),
                });
            }
            1 => {
                for _ in 0..2 {
                    events.event(NativeEvent::Source {
                        uri: text(OWNER_URL),
                    });
                }
            }
            2 => {
                events.event(NativeEvent::Content {
                    id: 2,
                    error_page: false,
                });
            }
            3 => {
                events.event(NativeEvent::Content {
                    id: 1,
                    error_page: true,
                });
            }
            4 => {
                for _ in 0..2 {
                    events.event(NativeEvent::Content {
                        id: 1,
                        error_page: false,
                    });
                }
            }
            5 => {
                events.event(NativeEvent::DomLoaded {
                    id: 2,
                    uri: text(OWNER_URL),
                });
            }
            6 => {
                events.event(NativeEvent::DomLoaded {
                    id: 1,
                    uri: text("about:blank"),
                });
            }
            7 => {
                for _ in 0..2 {
                    events.event(NativeEvent::DomLoaded {
                        id: 1,
                        uri: text(OWNER_URL),
                    });
                }
            }
            8 => {
                events.event(NativeEvent::NavigationCompleted {
                    id: 2,
                    success: true,
                });
            }
            9 => {
                events.event(NativeEvent::NavigationCompleted {
                    id: 1,
                    success: false,
                });
            }
            10 => {
                events.event(NativeEvent::Frame);
            }
            _ => {
                events.event(NativeEvent::ProcessFailed);
            }
        }
        assert!(events.invalid(), "case {case}");
    }
}

#[test]
fn resources_allow_only_the_document_and_controls_always_fail_closed() {
    let events = Events::default();
    assert_eq!(
        events.event(NativeEvent::Resource {
            uri: text(OWNER_URL),
            document: true
        }),
        NativeAction::Allow
    );
    for (uri, document) in [
        (OWNER_URL, false),
        ("http://localhost:49291/favicon.ico", true),
        ("https://example.invalid", false),
    ] {
        assert_eq!(
            events.event(NativeEvent::Resource {
                uri: text(uri),
                document
            }),
            NativeAction::BlockResource
        );
    }
    assert_eq!(events.blocked_resources(), 3);
    assert!(!events.invalid());
    for (event, action) in [
        (NativeEvent::NewWindow, NativeAction::Handled),
        (NativeEvent::Permission, NativeAction::Deny),
        (NativeEvent::Download, NativeAction::Cancel),
        (NativeEvent::ExternalUri, NativeAction::Cancel),
        (NativeEvent::Authentication, NativeAction::Cancel),
        (NativeEvent::ScriptDialog, NativeAction::Observe),
        (NativeEvent::CloseRequested, NativeAction::Observe),
    ] {
        let events = Events::default();
        assert_eq!(events.event(event), action);
        assert!(events.invalid());
    }
}

#[test]
fn every_failed_native_snapshot_refuses_and_records_controller_loss_once() {
    let error = NativeError {
        operation: Operation::Subscription,
        failure: Failure::CallFailed,
    };
    for (kind, expected) in [
        (EventKind::Navigation, NativeAction::Cancel),
        (EventKind::Source, NativeAction::Observe),
        (EventKind::Content, NativeAction::Observe),
        (EventKind::DomLoaded, NativeAction::Observe),
        (EventKind::NavigationCompleted, NativeAction::Observe),
        (EventKind::NewWindow, NativeAction::Handled),
        (EventKind::Permission, NativeAction::Deny),
        (EventKind::Download, NativeAction::Cancel),
        (EventKind::ExternalUri, NativeAction::Cancel),
        (EventKind::Authentication, NativeAction::Cancel),
        (EventKind::Resource, NativeAction::BlockResource),
        (EventKind::BrowserExited, NativeAction::Observe),
    ] {
        let events = Events::default();
        assert_eq!(events.failed(kind, error), expected);
        assert_eq!(events.failed(kind, error), expected);
        assert_eq!(events.take(), Some(SurfaceEvent::ControllerLost));
        assert_eq!(events.take(), None);
        assert!(events.invalid());
    }
}

#[test]
fn browser_exit_retains_only_matching_environment_identity() {
    let events = Events::default();
    events.expect_browser(7);
    events.event(NativeEvent::BrowserExited { pid: 8 });
    assert_eq!(events.exited(), None);
    assert!(!events.invalid());
    events.event(NativeEvent::BrowserExited { pid: 7 });
    assert_eq!(events.exited(), Some(7));
    assert!(events.invalid());
    let early = Events::default();
    early.event(NativeEvent::BrowserExited { pid: 7 });
    assert_eq!(early.exited(), Some(7));
    assert!(!early.invalid());
    early.expect_browser(8);
    assert!(!early.invalid());
    early.expect_browser(7);
    assert!(early.invalid());
    let zero = Events::default();
    zero.event(NativeEvent::BrowserExited { pid: 0 });
    assert_eq!(zero.exited(), None);
    assert_eq!(zero.take(), Some(SurfaceEvent::ControllerLost));
}

#[test]
fn callback_storm_collapses_to_one_loss_and_resource_count_saturates() {
    let events = Events::default();
    for _ in 0..=MAX_EVENTS {
        events.event(NativeEvent::Frame);
    }
    events.controller_lost();
    assert_eq!(events.take(), Some(SurfaceEvent::ControllerLost));
    assert_eq!(events.take(), None);
    assert!(events.invalid());
    events.blocked_resources.set(u32::MAX);
    assert_eq!(
        events.event(NativeEvent::Resource {
            uri: text("about:blank"),
            document: false
        }),
        NativeAction::BlockResource
    );
    assert_eq!(events.blocked_resources(), u32::MAX);
}

#[test]
fn already_exited_boundary_requires_one_own_exit_without_other_invalid_events() {
    let empty = Events::default();
    empty.expect_browser(42);
    assert!(!empty.matching_exit_at_boundary(42));

    let own = Events::default();
    own.expect_browser(42);
    own.event(NativeEvent::BrowserExited { pid: 42 });
    assert!(own.invalid());
    assert!(own.matching_exit_at_boundary(42));
    assert!(!own.matching_exit_at_boundary(43));
    assert_eq!(
        own.take(),
        Some(SurfaceEvent::BrowserExited { browser_pid: 42 })
    );
    assert!(own.matching_exit_at_boundary(42));

    let foreign = Events::default();
    foreign.expect_browser(42);
    foreign.event(NativeEvent::BrowserExited { pid: 43 });
    foreign.event(NativeEvent::BrowserExited { pid: 42 });
    assert!(!foreign.matching_exit_at_boundary(42));

    let prior = Events::default();
    prior.event(NativeEvent::BrowserExited { pid: 42 });
    prior.expect_browser(42);
    assert!(!prior.matching_exit_at_boundary(42));

    let other = Events::default();
    other.expect_browser(42);
    other.controller_lost();
    other.event(NativeEvent::BrowserExited { pid: 42 });
    assert!(!other.matching_exit_at_boundary(42));

    let duplicate = Events::default();
    duplicate.expect_browser(42);
    duplicate.event(NativeEvent::BrowserExited { pid: 42 });
    duplicate.event(NativeEvent::BrowserExited { pid: 42 });
    assert!(!duplicate.matching_exit_at_boundary(42));
}
