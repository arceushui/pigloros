#![cfg(windows)]
#![cfg(test)]

use std::cell::{Cell, RefCell};

use super::{control_denial::Control, unavailable, Result};
use crate::{ControlFault, ControlObservation, EventKind};
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2NavigationStartingEventArgs, ICoreWebView2ProcessFailedEventArgs,
    COREWEBVIEW2_PERMISSION_STATE, COREWEBVIEW2_PERMISSION_STATE_DENY,
    COREWEBVIEW2_PROCESS_FAILED_KIND, COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED,
};
use windows::core::BOOL;

std::thread_local! {
    static FAULT: Cell<(EventKind, ControlFault)> = const { Cell::new((EventKind::NewWindow, ControlFault::Normal)) };
    static OBSERVATIONS: RefCell<Vec<ControlObservation>> = const { RefCell::new(Vec::new()) };
    static PROCESS_FAILURES: RefCell<Vec<Option<bool>>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn process_failed(args: Option<&ICoreWebView2ProcessFailedEventArgs>) {
    let result = args.and_then(|args| {
        let mut kind = COREWEBVIEW2_PROCESS_FAILED_KIND::default();
        // SAFETY: actual ProcessFailed callback args on the invoking STA and
        // initialized enum output. This test-only read distinguishes the exact
        // owned view's main renderer exit from other native failure kinds.
        unsafe { args.ProcessFailedKind(&raw mut kind) }
            .ok()
            .map(|()| kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED)
    });
    PROCESS_FAILURES.with(|failures| failures.borrow_mut().push(result));
}

pub(super) fn mode(kind: EventKind) -> ControlFault {
    FAULT.with(|fault| {
        let (target, mode) = fault.get();
        if target == kind {
            mode
        } else {
            ControlFault::Normal
        }
    })
}

pub(super) fn begin(kind: EventKind) -> usize {
    OBSERVATIONS.with(|observations| {
        let mut observations = observations.borrow_mut();
        let id = observations.len();
        observations.push(ControlObservation {
            kind,
            deferred: false,
            attempts: 0,
            readback: None,
            completions: 0,
            retired: false,
        });
        id
    })
}

pub(super) fn update(id: usize, update: impl FnOnce(&mut ControlObservation)) {
    OBSERVATIONS.with(|observations| update(&mut observations.borrow_mut()[id]));
}

pub(super) fn readback(control: &Control) -> Result<bool> {
    let mut value = BOOL::default();
    match control {
        Control::NewWindow(args) => {
            let args = args.as_ref().ok_or_else(unavailable)?;
            // SAFETY: exact retained callback args, same STA; initialized BOOL
            // output, read only after the real Handled setter succeeded.
            unsafe { args.Handled(&raw mut value) }.map_err(|_| unavailable())?;
        }
        Control::Permission(args) => {
            let args = args.as_ref().ok_or_else(unavailable)?;
            let mut state = COREWEBVIEW2_PERMISSION_STATE::default();
            // SAFETY: exact retained callback args on this STA and initialized
            // enum output. No permission state is granted by this observation.
            unsafe { args.State(&raw mut state) }.map_err(|_| unavailable())?;
            return Ok(state == COREWEBVIEW2_PERMISSION_STATE_DENY);
        }
        Control::Download(args) => {
            let args = args.as_ref().ok_or_else(unavailable)?;
            // SAFETY: exact retained callback args on this STA; initialized
            // BOOL output, no download path or operation is read or accepted.
            unsafe { args.Cancel(&raw mut value) }.map_err(|_| unavailable())?;
        }
        Control::External(args) => {
            let args = args.as_ref().ok_or_else(unavailable)?;
            // SAFETY: exact retained callback args on this STA; initialized
            // BOOL output only, no URI is passed to an application launcher.
            unsafe { args.Cancel(&raw mut value) }.map_err(|_| unavailable())?;
        }
        Control::Authentication(args) => {
            let args = args.as_ref().ok_or_else(unavailable)?;
            // SAFETY: exact retained callback args on this STA; initialized
            // BOOL output only, no credential/response object is accessed.
            unsafe { args.Cancel(&raw mut value) }.map_err(|_| unavailable())?;
        }
        // Stop recovery does not claim to have changed the failed Cancel
        // property. Its SDK result and held ownership are separate evidence.
        Control::Navigation { .. } => return Ok(false),
    }
    Ok(value.as_bool())
}

pub(super) fn navigation(args: &ICoreWebView2NavigationStartingEventArgs) -> Result<()> {
    let id = begin(EventKind::Navigation);
    let mut value = BOOL::default();
    // SAFETY: actual invoking-STA navigation args, after Cancel=true succeeded;
    // initialized BOOL output. The observation never authorizes navigation.
    let result = unsafe { args.Cancel(&raw mut value) }.map_err(|_| unavailable());
    update(id, |record| {
        record.attempts = 1;
        record.readback = result.as_ref().ok().map(|()| value.as_bool());
        record.retired = true;
    });
    result
}

impl crate::Native {
    pub(crate) fn reset_process_failure_observations() {
        PROCESS_FAILURES.with(|failures| failures.borrow_mut().clear());
    }

    pub(crate) fn process_failure_observations() -> Vec<Option<bool>> {
        PROCESS_FAILURES.with(|failures| failures.borrow().clone())
    }

    pub(crate) fn set_control_fault(kind: EventKind, mode: ControlFault) {
        FAULT.with(|fault| fault.set((kind, mode)));
        OBSERVATIONS.with(|observations| observations.borrow_mut().clear());
    }

    pub(crate) fn control_observations() -> Vec<ControlObservation> {
        OBSERVATIONS.with(|observations| observations.borrow().clone())
    }
}
