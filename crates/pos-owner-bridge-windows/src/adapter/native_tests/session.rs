#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::time::Duration;

use super::super::events::Events;
use crate::{NativeFactory, NativeOperations, NativePulse, NativeResult};

/// A raw SDK fixture still owns a real environment on its creating STA when
/// an assertion unwinds. Keep that apartment borrowed until retirement, just
/// as the production host keeps a quarantined Surface.
pub(super) struct Session<'a> {
    native: Box<dyn NativeOperations>,
    events: Rc<Events>,
    factory: &'a dyn NativeFactory,
    browser_pid: Cell<Option<u32>>,
    had_controller: Cell<bool>,
}

impl<'a> Session<'a> {
    pub(super) fn new(factory: &'a dyn NativeFactory, events: Rc<Events>) -> NativeResult<Self> {
        factory.session().map(|native| Self {
            native,
            events,
            factory,
            browser_pid: Cell::new(None),
            had_controller: Cell::new(false),
        })
    }

    pub(super) fn controller_completion(&mut self) -> Option<NativeResult<()>> {
        let completion = self.native.controller_completion();
        if completion.as_ref().is_some_and(Result::is_ok) {
            self.had_controller.set(true);
        }
        completion
    }

    pub(super) fn browser_pid(&self) -> NativeResult<u32> {
        self.native.browser_pid().inspect(|pid| {
            if *pid != 0 {
                self.browser_pid.set(Some(*pid));
                self.events.expect_browser(*pid);
            }
        })
    }

    pub(super) fn as_mut(&mut self) -> &mut (dyn NativeOperations + 'static) {
        self.native.as_mut()
    }

    pub(super) fn as_ref(&self) -> &(dyn NativeOperations + 'static) {
        self.native.as_ref()
    }

    fn pump_retaining(&self) {
        if !matches!(
            self.factory.next(),
            Ok(NativePulse::Timer | NativePulse::Dispatched)
        ) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Deref for Session<'_> {
    type Target = dyn NativeOperations;

    fn deref(&self) -> &Self::Target {
        self.native.as_ref()
    }
}

impl DerefMut for Session<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.native.as_mut()
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        loop {
            let _zeroed_or_retained = self.native.close_buffers();
            let _environment = self.native.environment_completion();
            let _controller = self.controller_completion();
            if !self.native.pending() {
                if let Ok(has_controller) = self.native.has_controller() {
                    self.had_controller
                        .set(self.had_controller.get() || has_controller);
                    if has_controller && self.browser_pid.get().is_none() {
                        let _identity_or_retained = self.browser_pid();
                    }
                    let exited = self
                        .browser_pid
                        .get()
                        .is_some_and(|expected| self.events.exited() == Some(expected));
                    if !self.had_controller.get() || exited {
                        // A failed pre-controller creation leaves its recordless
                        // folder intact. A controller requires its own exit event.
                        if self.native.unsubscribe_view().is_ok()
                            && self.native.unsubscribe_exit().is_ok()
                            && self.native.drop_environment().is_ok()
                            && self.native.destroy_window().is_ok()
                        {
                            break;
                        }
                    } else if self.browser_pid.get().is_some() {
                        let _subscribed_or_removed = self.native.unsubscribe_view();
                        let _closed_or_retained = self.native.close_controller();
                    }
                }
            }
            self.pump_retaining();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::native_tests::pass;
    use crate::adapter::surface::tests::native::{Creation, Factory};
    use crate::{EventSink, NativeEvent, StaPump};
    use pos_owner_bridge::fake::clock::FakeClock;

    struct RecoveringFactory {
        native: Rc<Factory>,
        events: Rc<Events>,
        pumps: Cell<u8>,
    }

    impl StaPump for RecoveringFactory {
        fn next(&self) -> NativeResult<NativePulse> {
            let calls = self.native.calls.borrow();
            assert!(!calls.contains(&"unsubscribe_exit"));
            assert!(!calls.contains(&"drop_environment"));
            let pump = self.pumps.get();
            self.pumps.set(pump + 1);
            if pump == 0 {
                // The getter must be recoverable: the controller is still held.
                assert!(!calls.contains(&"close_controller"));
                self.native.creation.set(Creation::Ready);
            } else {
                assert_eq!(
                    pump, 1,
                    "raw session did not retire after the matching exit"
                );
                assert!(calls.contains(&"close_controller"));
                self.events.event(NativeEvent::BrowserExited { pid: 42 });
            }
            Ok(NativePulse::Timer)
        }

        fn stop(&mut self) -> NativeResult<()> {
            Ok(())
        }
    }

    impl NativeFactory for RecoveringFactory {
        fn session(&self) -> NativeResult<Box<dyn NativeOperations>> {
            self.native.session()
        }
    }

    // This scripted factory models host ownership and cleanup; it does not
    // claim that the native SDK returned a particular failure or callback.
    struct PendingOrBlockedFactory {
        native: Rc<Factory>,
        failing: Option<&'static str>,
        forbidden: &'static [&'static str],
        pumps: Cell<u8>,
    }

    impl StaPump for PendingOrBlockedFactory {
        fn next(&self) -> NativeResult<NativePulse> {
            assert_eq!(self.pumps.get(), 0, "modeled recovery did not progress");
            self.pumps.set(1);
            let calls = self.native.calls.borrow();
            if let Some(failing) = self.failing {
                assert!(calls.contains(&failing));
            }
            for forbidden in self.forbidden {
                assert!(
                    !calls.contains(forbidden),
                    "released {forbidden} before recovery"
                );
            }
            drop(calls);
            if self.failing.is_some() {
                self.native.failure.set(None);
            } else {
                self.native.creation.set(Creation::CallbackFailure);
            }
            // The keeper must retain all owners even after the pump reports quit.
            Ok(NativePulse::Quit)
        }

        fn stop(&mut self) -> NativeResult<()> {
            Ok(())
        }
    }

    impl NativeFactory for PendingOrBlockedFactory {
        fn session(&self) -> NativeResult<Box<dyn NativeOperations>> {
            self.native.session()
        }
    }

    #[test]
    fn modeled_pending_controller_and_quit_retain_owners_until_completion() {
        let native = Factory::new(Creation::Pending, FakeClock::start());
        let mut factory = PendingOrBlockedFactory {
            native: Rc::clone(&native),
            failing: None,
            forbidden: &[
                "unsubscribe_view",
                "unsubscribe_exit",
                "drop_environment",
                "destroy_window",
            ],
            pumps: Cell::new(0),
        };
        let session = Session::new(&factory, Rc::new(Events::default())).map(|mut session| {
            let created = session.create_controller();
            assert!(created.is_ok(), "controller creation: {created:?}");
            session
        });
        let error = session.as_ref().err();
        assert!(session.is_ok(), "session creation: {error:?}");
        drop(session);
        assert_eq!(factory.pumps.get(), 1);
        let calls = native.calls.borrow();
        assert!(!calls.contains(&"close_controller"));
        assert!(calls.contains(&"drop_environment"));
        assert!(calls.contains(&"destroy_window"));
        assert!(factory.stop().is_ok());
    }

    #[test]
    fn modeled_teardown_failure_retains_later_owners_until_retry() {
        for (failing, forbidden) in [
            (
                "unsubscribe_view",
                &["unsubscribe_exit", "drop_environment", "destroy_window"][..],
            ),
            (
                "unsubscribe_exit",
                &["drop_environment", "destroy_window"][..],
            ),
            ("drop_environment", &["destroy_window"][..]),
            ("destroy_window", &[][..]),
        ] {
            let native = Factory::new(Creation::Ready, FakeClock::start());
            native.failure.set(Some(failing));
            let mut factory = PendingOrBlockedFactory {
                native: Rc::clone(&native),
                failing: Some(failing),
                forbidden,
                pumps: Cell::new(0),
            };
            let session = Session::new(&factory, Rc::new(Events::default()));
            let error = session.as_ref().err();
            assert!(session.is_ok(), "session creation: {error:?}");
            drop(session);
            assert_eq!(factory.pumps.get(), 1, "{failing}");
            let calls = native.calls.borrow();
            assert_eq!(
                calls.iter().filter(|call| **call == failing).count(),
                2,
                "{failing}"
            );
            assert!(calls.contains(&"destroy_window"));
            assert!(!calls.contains(&"close_controller"));
            assert!(factory.stop().is_ok(), "{failing}");
        }
    }

    #[test]
    fn raw_session_retains_unknown_pid_until_its_matching_exit() {
        let native = Factory::new(Creation::Ready, FakeClock::start());
        let events = Rc::new(Events::default());
        let mut factory = RecoveringFactory {
            native: Rc::clone(&native),
            events: Rc::clone(&events),
            pumps: Cell::new(0),
        };
        let result = Session::new(&factory, Rc::clone(&events)).map(|mut session| {
            let created = session.create_controller();
            assert!(created.is_ok(), "controller creation: {created:?}");
            assert_eq!(session.controller_completion(), Some(Ok(())));
            native.creation.set(Creation::MissingView);
            events.event(NativeEvent::BrowserExited { pid: 99 });
            drop(session);
            assert_eq!(factory.pumps.get(), 2);
            let calls = native.calls.borrow();
            let close = calls.iter().position(|call| *call == "close_controller");
            let unsubscribe = calls.iter().position(|call| *call == "unsubscribe_exit");
            let drop_environment = calls.iter().position(|call| *call == "drop_environment");
            assert!(close.is_some(), "no close");
            assert!(unsubscribe.is_some(), "no exit unsubscribe");
            assert!(drop_environment.is_some(), "no environment drop");
            assert!(close < unsubscribe && unsubscribe < drop_environment);
        });
        assert!(result.is_ok(), "session creation: {result:?}");
        assert!(factory.stop().is_ok());
    }

    #[test]
    fn raw_session_without_controller_retires_without_an_exit() {
        let native = Factory::new(Creation::Ready, FakeClock::start());
        let events = Rc::new(Events::default());
        let session = Session::new(&native, events);
        let error = session.as_ref().err();
        assert!(session.is_ok(), "session creation: {error:?}");
        drop(session);
        assert!(native.calls.borrow().contains(&"drop_environment"));
    }

    #[test]
    fn idle_native_session_refuses_operations_until_their_owners_exist() {
        let _port = crate::Native::fixed_port_fixture();
        let mut factory = pass(crate::Native::owner_factory());
        let events = Rc::new(Events::default());
        let sink: Rc<dyn EventSink> = events.clone();
        let mut session = pass(Session::new(&factory, events));
        let closed = crate::NativeError {
            operation: crate::Operation::Controller,
            failure: crate::Failure::Closed,
        };
        let mut reply = pos_owner_bridge::ReplyImage::zeroed();
        let assert_closed = |operation: &str, result: NativeResult<()>| {
            assert_eq!(result, Err(closed), "{operation}");
        };
        assert_closed("resize_window", session.resize_window(480, 640, 96));
        assert_closed("show_window", session.show_window());
        assert_closed("fit_controller", session.fit_controller());
        assert_closed("focus_controller", session.focus_controller());
        assert_closed("create_controller", session.create_controller());
        assert_closed(
            "require_shared_interfaces",
            session.require_shared_interfaces(),
        );
        assert_closed("subscribe_view", session.subscribe_view(Rc::clone(&sink)));
        assert_closed(
            "set_bool",
            session.set_bool(crate::BoolProperty::Script, true),
        );
        assert_closed("navigate_owner", session.navigate_owner());
        assert_closed(
            "create_buffers",
            session.create_buffers(pos_owner_bridge_codec::CeremonyKind::Get, &[], &[0; 64]),
        );
        assert_closed("post_request", session.post(crate::BufferSlot::Request));
        assert_closed("post_reply", session.post(crate::BufferSlot::Reply));
        assert_closed("copy_reply", session.copy_reply(&mut reply));
        assert_eq!(session.window().err(), Some(closed));
        assert_eq!(session.environment().err(), Some(closed));
        assert_eq!(session.browser_pid().err(), Some(closed));
        assert_eq!(session.get_bool(crate::BoolProperty::Script), Err(closed));
        assert_eq!(session.source().err(), Some(closed));
        assert_eq!(session.load_state(), Err(closed));
        assert_eq!(session.compare_exchange(0, 1), Err(closed));
        let invalid_environment = crate::NativeError {
            operation: crate::Operation::Environment,
            failure: crate::Failure::CallFailed,
        };
        for (runtime, folder) in [
            ("", "folder"),
            ("bad\0runtime", "folder"),
            ("runtime", ""),
            ("runtime", "bad\0folder"),
        ] {
            assert_eq!(
                session.create_environment(
                    std::path::Path::new(runtime),
                    std::path::Path::new(folder),
                    crate::adapter::settings::OPTIONS,
                    Rc::clone(&sink),
                ),
                Err(invalid_environment)
            );
            assert!(!session.pending());
            assert!(session.environment_completion().is_none());
            assert!(session.environment_creation_completion().is_none());
            assert_eq!(session.environment().err(), Some(closed));
        }
        assert!(reply.as_bytes().iter().all(|byte| *byte == 0));
        assert!(session.environment_completion().is_none());
        assert!(session.controller_completion().is_none());
        assert!(session.environment_creation_completion().is_none());
        assert!(session.recordless_controller_completion().is_none());
        assert!(session.early_renderer_presence().is_err());
        assert!(session.pending_opening_browser_candidate().is_err());
        assert!(session.recordless_browser_candidate().is_err());
        assert!(!session.pending());
        assert!(!pass(session.has_controller()));
        assert!(!session.buffer_close_uncertain());
        assert!(!session.preload_fault_owners_retained());
        assert!(!session.pending_opening_owners_retained());
        assert!(!session.recordless_fault_owners_retained());
        assert!(!session.fault_owners_retained());
        assert!(!session.exit_fault_owners_retained());
        for _ in 0..2 {
            pass(session.close_buffers());
            pass(session.unsubscribe_view());
            pass(session.close_controller());
            pass(session.unsubscribe_exit());
            pass(session.drop_environment());
            pass(session.destroy_window());
        }
        drop(session);
        pass(factory.stop());
    }
}
