#![cfg(windows)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Deferral, ICoreWebView2WebResourceRequestedEventArgs,
};

use super::{unavailable, Result};
use crate::{EventKind, EventSink, NativeAction, NativeError, NativeEvent};

/// Resource and ADR-130 control owners. Each instance belongs to one fresh
/// environment and is advanced only by its creating STA's outer loop.
pub(in crate::ffi) struct Recovery {
    last_retry: Cell<Option<u64>>,
    expected_pid: Cell<Option<u32>>,
    exited: Cell<bool>,
    pending: RefCell<Vec<Held>>,
    controls: RefCell<Vec<super::control_denial::Held>>,
    // Keep the creator apartment alive through every retained COM release.
    token: Rc<super::super::pump::StaToken>,
}

impl Recovery {
    pub(in crate::ffi) const fn new(token: Rc<super::super::pump::StaToken>) -> Self {
        Self {
            token,
            last_retry: Cell::new(None),
            expected_pid: Cell::new(None),
            exited: Cell::new(false),
            pending: RefCell::new(Vec::new()),
            controls: RefCell::new(Vec::new()),
        }
    }

    pub(in crate::ffi) fn expect_browser(&self, pid: u32) {
        self.expected_pid.set(Some(pid));
    }

    pub(super) fn control(
        &self,
        control: super::control_denial::Control,
        view: ICoreWebView2,
        sink: Rc<dyn EventSink>,
    ) {
        let mut held = super::control_denial::Held::new(control, view, sink);
        if !held.advance() && !self.exited.get() {
            self.controls.borrow_mut().push(held);
        }
    }

    pub(super) fn deny(
        &self,
        args: Option<ICoreWebView2WebResourceRequestedEventArgs>,
        view: ICoreWebView2,
        signals: Rc<dyn EventSink>,
    ) {
        let deferral = args.as_ref().and_then(|args| match defer_request(args) {
            Ok(deferral) => Some(deferral),
            Err(error) => {
                signals.failed(EventKind::Resource, error);
                None
            }
        });
        let mut held = Held {
            _args: args,
            view,
            deferral,
            signals,
            stopped: false,
            completed: false,
            #[cfg(test)]
            stop_failures: if matches!(
                super::resource::fixture(),
                crate::ResourceDenialFixture::RetryStop | crate::ResourceDenialFixture::DriverRetry
            ) {
                3
            } else {
                0
            },
        };
        if !held.advance() && !self.exited.get() {
            self.pending.borrow_mut().push(held);
        }
    }

    /// No `RefCell` borrow crosses a COM call: Stop/Complete can dispatch another
    /// callback. Uncertain Complete owners remain held, but known cancellation
    /// allows Close so the exact `BrowserProcessExited` can retire those owners.
    pub(in crate::ffi) fn retry(&self) -> Result<()> {
        if self.exited.get() {
            return Ok(());
        }
        // Stamp before any COM call, which may dispatch reentrant callbacks.
        // Unsubscribe, Close and repeated event draining within the same outer
        // pump progression only inspect containment after this first retry.
        if self.last_retry.replace(Some(self.token.progress())) == Some(self.token.progress()) {
            return self.contained();
        }
        let pending = std::mem::take(&mut *self.pending.borrow_mut());
        let retained: Vec<_> = pending
            .into_iter()
            .filter_map(|mut held| (!held.advance()).then_some(held))
            .collect();
        if self.exited.get() {
            return Ok(());
        }
        self.pending.borrow_mut().extend(retained);
        let controls = std::mem::take(&mut *self.controls.borrow_mut());
        let retained: Vec<_> = controls
            .into_iter()
            .filter_map(|mut held| (!held.advance()).then_some(held))
            .collect();
        if self.exited.get() {
            return Ok(());
        }
        self.controls.borrow_mut().extend(retained);
        self.contained()
    }

    fn contained(&self) -> Result<()> {
        if self.pending.borrow().iter().all(|held| held.stopped)
            && self.controls.borrow().iter().all(|held| held.denied)
        {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn exited(&self, pid: u32) {
        if self.expected_pid.get() == Some(pid) {
            self.exited.set(true);
            let retired = std::mem::take(&mut *self.pending.borrow_mut());
            let controls = std::mem::take(&mut *self.controls.borrow_mut());
            drop(retired);
            drop(controls);
        }
    }
}

struct Held {
    _args: Option<ICoreWebView2WebResourceRequestedEventArgs>,
    view: ICoreWebView2,
    deferral: Option<ICoreWebView2Deferral>,
    signals: Rc<dyn EventSink>,
    stopped: bool,
    completed: bool,
    #[cfg(test)]
    stop_failures: u8,
}

impl Held {
    // True means all owners can be released. A failed Complete is attempted
    // once only, even when later outer-loop cleanup retries cancellation.
    fn advance(&mut self) -> bool {
        if !self.stopped {
            // Model failed cancellation without invoking Stop: the acquired
            // real deferral must itself prevent contact until the outer retry.
            #[cfg(test)]
            if self.stop_failures > 0 {
                self.stop_failures -= 1;
                self.signals.failed(EventKind::Resource, unavailable());
                return false;
            }
            let stopped = stop_fetches(&self.view);
            if !super::report_result(self.signals.as_ref(), EventKind::Resource, stopped) {
                return false;
            }
            self.stopped = true;
        }
        let Some(deferral) = &self.deferral else {
            return true;
        };
        if self.completed {
            return false;
        }
        self.completed = true;
        let completed = complete_request(deferral);
        super::report_result(self.signals.as_ref(), EventKind::Resource, completed)
    }
}

pub(super) fn stop_fetches(view: &ICoreWebView2) -> Result<()> {
    // SAFETY: exact intercepted session's retained view on its creating STA;
    // resource denial or failed mandatory navigation Cancel (ADR-130) only.
    // The HRESULT determines whether Close/subscription removal is permitted.
    unsafe { view.Stop() }.map_err(|_| unavailable())
}

fn defer_request(
    args: &ICoreWebView2WebResourceRequestedEventArgs,
) -> Result<ICoreWebView2Deferral> {
    #[cfg(test)]
    if super::resource::fixture() == crate::ResourceDenialFixture::MissingDeferral {
        return Err(unavailable());
    }
    // SAFETY: owned arguments from the live WebResourceRequested callback on
    // this STA. The returned deferral is retained with those arguments/view.
    unsafe { args.GetDeferral() }.map_err(|_| unavailable())
}

pub(super) fn complete_request(deferral: &ICoreWebView2Deferral) -> Result<()> {
    #[cfg(test)]
    {
        COMPLETE_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
        if super::resource::fixture() == crate::ResourceDenialFixture::UncertainComplete {
            return Err(unavailable());
        }
    }
    // SAFETY: retained request deferral on its creating STA, after successful
    // Stop or the event's mandatory denial only (ADR-130). The owner marks
    // this attempt before COM; it cannot run twice.
    unsafe { deferral.Complete() }.map_err(|_| unavailable())
}

#[cfg(test)]
std::thread_local! {
    static COMPLETE_ATTEMPTS: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_fixture() {
    COMPLETE_ATTEMPTS.with(|attempts| attempts.set(0));
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn resource_deferral_completion_attempts() -> u32 {
        COMPLETE_ATTEMPTS.with(Cell::get)
    }
}

pub(in crate::ffi) fn track_exit(
    sink: Rc<dyn EventSink>,
    recovery: Rc<Recovery>,
) -> Rc<dyn EventSink> {
    Rc::new(Exit { sink, recovery })
}

struct Exit {
    sink: Rc<dyn EventSink>,
    recovery: Rc<Recovery>,
}

impl EventSink for Exit {
    fn event(&self, event: NativeEvent) -> NativeAction {
        if let NativeEvent::BrowserExited { pid } = &event {
            self.recovery.exited(*pid);
        }
        self.sink.event(event)
    }

    fn failed(&self, kind: EventKind, error: NativeError) -> NativeAction {
        self.sink.failed(kind, error)
    }
}
