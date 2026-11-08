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
            self.browser_pid.set(Some(*pid));
            self.events.expect_browser(*pid);
        })
    }

    pub(super) fn as_mut(&mut self) -> &mut (dyn NativeOperations + 'static) {
        self.native.as_mut()
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
                    let exited = self.events.exited().is_some_and(|pid| {
                        self.browser_pid
                            .get()
                            .is_none_or(|expected| expected == pid)
                    });
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
                    } else {
                        let _subscribed_or_removed = self.native.unsubscribe_view();
                        let _closed_or_retained = self.native.close_controller();
                    }
                }
            }
            self.pump_retaining();
        }
    }
}
