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
        let mut iteration = 0_u32;
        loop {
            let report = iteration == 0 || iteration.is_power_of_two();
            if report {
                super::diagnostic(format_args!(
                    "raw.retire.close_buffers iteration={iteration}"
                ));
            }
            let _zeroed_or_retained = self.native.close_buffers();
            if report {
                super::diagnostic(format_args!("raw.retire.completions iteration={iteration}"));
            }
            let _environment = self.native.environment_completion();
            let _controller = self.controller_completion();
            if report {
                super::diagnostic(format_args!(
                    "raw.retire.cached iteration={iteration} pid={:?} had_controller={} exited={:?}",
                    self.browser_pid.get(), self.had_controller.get(), self.events.exited()
                ));
            }
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
                            super::diagnostic(format_args!("raw.retire.complete"));
                            break;
                        }
                    } else if self.browser_pid.get().is_some() {
                        let _subscribed_or_removed = self.native.unsubscribe_view();
                        let _closed_or_retained = self.native.close_controller();
                    }
                }
            }
            if report {
                super::diagnostic(format_args!("raw.retire.pump.enter iteration={iteration}"));
            }
            self.pump_retaining();
            if report {
                super::diagnostic(format_args!(
                    "raw.retire.pump.complete iteration={iteration}"
                ));
            }
            iteration = iteration.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn raw_session_retains_unknown_pid_until_its_matching_exit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let native = Factory::new(Creation::Ready, FakeClock::start());
        let events = Rc::new(Events::default());
        let factory = RecoveringFactory {
            native: Rc::clone(&native),
            events: Rc::clone(&events),
            pumps: Cell::new(0),
        };
        let mut session =
            Session::new(&factory, Rc::clone(&events)).map_err(|e| format!("{e:?}"))?;
        session.create_controller().map_err(|e| format!("{e:?}"))?;
        assert!(matches!(session.controller_completion(), Some(Ok(()))));
        native.creation.set(Creation::MissingView);
        events.event(NativeEvent::BrowserExited { pid: 99 });
        drop(session);
        assert_eq!(factory.pumps.get(), 2);
        let calls = native.calls.borrow();
        let close = calls
            .iter()
            .position(|call| *call == "close_controller")
            .ok_or("no close")?;
        let unsubscribe = calls
            .iter()
            .position(|call| *call == "unsubscribe_exit")
            .ok_or("no exit unsubscribe")?;
        let drop_environment = calls
            .iter()
            .position(|call| *call == "drop_environment")
            .ok_or("no environment drop")?;
        assert!(close < unsubscribe && unsubscribe < drop_environment);
        Ok(())
    }

    #[test]
    fn raw_session_without_controller_retires_without_an_exit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let native = Factory::new(Creation::Ready, FakeClock::start());
        let events = Rc::new(Events::default());
        let session = Session::new(&native, events).map_err(|e| format!("{e:?}"))?;
        drop(session);
        assert!(native.calls.borrow().contains(&"drop_environment"));
        Ok(())
    }

    #[test]
    fn idle_native_session_refuses_operations_until_their_owners_exist(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _port = crate::Native::fixed_port_fixture();
        let mut factory = crate::Native::owner_factory()?;
        let events = Rc::new(Events::default());
        let sink: Rc<dyn EventSink> = events.clone();
        let mut session = Session::new(&factory, events)?;
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
        assert_closed("subscribe_view", session.subscribe_view(sink));
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
        assert!(reply.as_bytes().iter().all(|byte| *byte == 0));
        assert!(session.environment_completion().is_none());
        assert!(session.controller_completion().is_none());
        assert!(session.environment_creation_completion().is_none());
        assert!(session.recordless_controller_completion().is_none());
        assert!(session.early_renderer_presence().is_err());
        assert!(session.pending_opening_browser_candidate().is_err());
        assert!(session.recordless_browser_candidate().is_err());
        assert!(!session.pending());
        assert!(!session.has_controller()?);
        assert!(!session.buffer_close_uncertain());
        assert!(!session.preload_fault_owners_retained());
        assert!(!session.pending_opening_owners_retained());
        assert!(!session.recordless_fault_owners_retained());
        assert!(!session.fault_owners_retained());
        assert!(!session.exit_fault_owners_retained());
        for _ in 0..2 {
            session.close_buffers()?;
            session.unsubscribe_view()?;
            session.close_controller()?;
            session.unsubscribe_exit()?;
            session.drop_environment()?;
            session.destroy_window()?;
        }
        drop(session);
        factory.stop()?;
        Ok(())
    }
}
