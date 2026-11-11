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
    static PROCESS_FAILURES: RefCell<Vec<crate::NativeProcessFailure>> = const { RefCell::new(Vec::new()) };
    static RENDERER_STATES: RefCell<Vec<crate::RendererStateObservation>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn process_failed(args: Option<&ICoreWebView2ProcessFailedEventArgs>) {
    use crate::NativeProcessFailure;
    use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED;
    let result = args
        .and_then(|args| {
            let mut kind = COREWEBVIEW2_PROCESS_FAILED_KIND::default();
            // SAFETY: actual ProcessFailed callback args on the invoking STA and
            // initialized enum output. This test-only read distinguishes the exact
            // owned view's main renderer exit from other native failure kinds.
            unsafe { args.ProcessFailedKind(&raw mut kind) }
                .ok()
                .map(|()| match kind {
                    COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED => {
                        NativeProcessFailure::MainRendererExited
                    }
                    COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED => {
                        NativeProcessFailure::BrowserExited
                    }
                    _ => NativeProcessFailure::Other,
                })
        })
        .unwrap_or(NativeProcessFailure::Unavailable);
    PROCESS_FAILURES.with(|failures| push_observation(failures, result));
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
        if id >= MAX_OBSERVATIONS {
            if let Some(last) = observations.last_mut() {
                last.overflowed = true;
            }
            return usize::MAX;
        }
        observations.push(ControlObservation {
            kind,
            deferred: false,
            attempts: 0,
            readback: None,
            completions: 0,
            retired: false,
            overflowed: false,
        });
        id
    })
}

pub(super) fn update(id: usize, update: impl FnOnce(&mut ControlObservation)) {
    OBSERVATIONS.with(|observations| {
        let mut observations = observations.borrow_mut();
        if let Some(observation) = observations.get_mut(id) {
            update(observation);
        }
    });
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
    // Scripted classification for model tests only; it grants no native fault authority.
    pub(crate) fn model_main_renderer_exit() {
        PROCESS_FAILURES.with(|failures| {
            push_observation(failures, crate::NativeProcessFailure::MainRendererExited);
        });
    }

    pub(crate) fn reset_process_failure_observations() {
        PROCESS_FAILURES.with(|failures| failures.borrow_mut().clear());
        RENDERER_STATES.with(|states| states.borrow_mut().clear());
    }

    pub(crate) fn record_renderer_state(state: crate::RendererStateObservation) {
        RENDERER_STATES.with(|states| push_observation(states, state));
    }

    pub(crate) fn renderer_state_observations() -> Vec<crate::RendererStateObservation> {
        RENDERER_STATES.with(|states| states.borrow().clone())
    }

    pub(crate) fn process_failure_observations() -> Vec<Option<bool>> {
        use crate::NativeProcessFailure;
        PROCESS_FAILURES.with(|failures| {
            failures
                .borrow()
                .iter()
                .map(|failure| match failure {
                    NativeProcessFailure::MainRendererExited => Some(true),
                    NativeProcessFailure::BrowserExited | NativeProcessFailure::Other => {
                        Some(false)
                    }
                    NativeProcessFailure::Unavailable => None,
                })
                .collect()
        })
    }

    pub(crate) fn classified_process_failure_observations() -> Vec<crate::NativeProcessFailure> {
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

// Process-failure and renderer-state consumers accept at most one observation.
// Control observations can use both slots; further callbacks set an overflow
// flag so a bounded snapshot cannot hide an extra control callback.
const MAX_OBSERVATIONS: usize = 2;

fn push_observation<T>(observations: &RefCell<Vec<T>>, value: T) {
    let mut observations = observations.borrow_mut();
    if observations.len() < MAX_OBSERVATIONS {
        observations.push(value);
    }
}

#[test]
fn repeated_callbacks_remain_failed_evidence_without_unbounded_storage() {
    use crate::{Native, NativeProcessFailure, RendererStateObservation};

    Native::set_control_fault(EventKind::Navigation, ControlFault::Normal);
    Native::reset_process_failure_observations();
    let missing_state = RendererStateObservation {
        generation: None,
        reply_state: None,
        record_count: None,
    };
    for _ in 0..10_000 {
        let id = begin(EventKind::Navigation);
        update(id, |record| record.attempts += 1);
        process_failed(None);
        Native::record_renderer_state(missing_state);
    }
    let controls = Native::control_observations();
    assert_eq!(controls.len(), MAX_OBSERVATIONS);
    assert!(controls.iter().all(|record| record.attempts == 1));
    assert!(!controls[0].overflowed);
    assert!(controls[1].overflowed);
    update(1, |record| record.retired = true);
    assert!(Native::control_observations()[1].overflowed);
    assert_eq!(
        Native::classified_process_failure_observations(),
        [NativeProcessFailure::Unavailable; MAX_OBSERVATIONS]
    );
    assert_eq!(
        Native::renderer_state_observations(),
        [missing_state; MAX_OBSERVATIONS]
    );
    Native::set_control_fault(EventKind::Navigation, ControlFault::Normal);
    Native::reset_process_failure_observations();
}
