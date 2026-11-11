#![cfg(windows)]

use std::rc::Rc;

use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2BasicAuthenticationRequestedEventArgs, ICoreWebView2Deferral,
    ICoreWebView2DownloadStartingEventArgs, ICoreWebView2LaunchingExternalUriSchemeEventArgs,
    ICoreWebView2NavigationStartingEventArgs, ICoreWebView2NewWindowRequestedEventArgs,
    ICoreWebView2PermissionRequestedEventArgs, COREWEBVIEW2_PERMISSION_STATE_DENY,
};

use super::{unavailable, Result};
use crate::{EventKind, EventSink};

/// The closed ADR-130 event families. Navigation has already attempted its
/// mandatory Cancel and uses Stop; it has no SDK deferral operation.
pub(super) enum Control {
    NewWindow(Option<ICoreWebView2NewWindowRequestedEventArgs>),
    Permission(Option<ICoreWebView2PermissionRequestedEventArgs>),
    Download(Option<ICoreWebView2DownloadStartingEventArgs>),
    External(Option<ICoreWebView2LaunchingExternalUriSchemeEventArgs>),
    Authentication(Option<ICoreWebView2BasicAuthenticationRequestedEventArgs>),
    Navigation {
        _args: Option<ICoreWebView2NavigationStartingEventArgs>,
    },
}

impl Control {
    const fn kind(&self) -> EventKind {
        match self {
            Self::NewWindow(_) => EventKind::NewWindow,
            Self::Permission(_) => EventKind::Permission,
            Self::Download(_) => EventKind::Download,
            Self::External(_) => EventKind::ExternalUri,
            Self::Authentication(_) => EventKind::Authentication,
            Self::Navigation { .. } => EventKind::Navigation,
        }
    }

    fn defer(&self) -> Result<Option<ICoreWebView2Deferral>> {
        #[cfg(test)]
        if super::control_fixture::mode(self.kind()) == crate::ControlFault::MissingDeferral {
            return Err(unavailable());
        }
        let deferral = match self {
            Self::NewWindow(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: owned invoking-STA popup arguments, before SetHandled;
                // retain this event-specific deferral with args and exact view.
                unsafe { args.GetDeferral() }
            }
            Self::Permission(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: owned invoking-STA permission arguments, before DENY;
                // this hold is for this request, not a global permission grant.
                unsafe { args.GetDeferral() }
            }
            Self::Download(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: owned invoking-STA download arguments, before Cancel;
                // no path, acceptance or download operation is requested.
                unsafe { args.GetDeferral() }
            }
            Self::External(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: owned invoking-STA external-URI arguments, before
                // Cancel; no external application launch is authorized.
                unsafe { args.GetDeferral() }
            }
            Self::Authentication(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: owned invoking-STA authentication arguments, before
                // Cancel; no credentials are read, written or accepted.
                unsafe { args.GetDeferral() }
            }
            Self::Navigation { .. } => return Ok(None),
        };
        deferral.map(Some).map_err(|_| unavailable())
    }

    fn deny(&self, view: &ICoreWebView2) -> Result<()> {
        let result = match self {
            Self::NewWindow(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: retained invoking-STA args; fixed Handled=true and no
                // assigned NewWindow suppress this pending popup request.
                unsafe { args.SetHandled(true) }
            }
            Self::Permission(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: retained invoking-STA args; the only state is DENY.
                unsafe { args.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY) }
            }
            Self::Download(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: retained invoking-STA args; Cancel=true, never a path
                // change or acceptance of the download.
                unsafe { args.SetCancel(true) }
            }
            Self::External(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: retained invoking-STA args; Cancel=true prevents the
                // external launch. No untrusted URI is passed to an OS launcher.
                unsafe { args.SetCancel(true) }
            }
            Self::Authentication(args) => {
                let args = args.as_ref().ok_or_else(unavailable)?;
                // SAFETY: retained invoking-STA args; Cancel=true, no credential
                // or response object is read or provided.
                unsafe { args.SetCancel(true) }
            }
            Self::Navigation { .. } => return super::denial::stop_fetches(view),
        };
        result.map_err(|_| unavailable())
    }
}

pub(super) struct Held {
    control: Control,
    view: ICoreWebView2,
    deferral: Option<ICoreWebView2Deferral>,
    sink: Rc<dyn EventSink>,
    pub(super) denied: bool,
    completed: bool,
    #[cfg(test)]
    observation: usize,
    #[cfg(test)]
    failures_left: u8,
}

impl Held {
    pub(super) fn new(control: Control, view: ICoreWebView2, sink: Rc<dyn EventSink>) -> Self {
        #[cfg(test)]
        let observation = super::control_fixture::begin(control.kind());
        // Even failed acquisition must still attempt the mandatory denial.
        let acquisition = control.defer();
        let deferral = match acquisition {
            Ok(deferral) => deferral,
            Err(error) => {
                sink.failed(control.kind(), error);
                None
            }
        };
        #[cfg(test)]
        super::control_fixture::update(observation, |record| record.deferred = deferral.is_some());
        #[cfg(test)]
        let failures_left = u8::from(
            super::control_fixture::mode(control.kind()) == crate::ControlFault::RetryDenial,
        ) * 3;
        Self {
            control,
            view,
            deferral,
            sink,
            denied: false,
            completed: false,
            #[cfg(test)]
            observation,
            #[cfg(test)]
            failures_left,
        }
    }

    /// Return true only when all event owners can retire. A known denial
    /// permits Close even when Complete was uncertain; an unresolved denial
    /// retains every owner and vetoes both Close and subscription removal.
    pub(super) fn advance(&mut self) -> bool {
        if !self.denied {
            #[cfg(test)]
            {
                super::control_fixture::update(self.observation, |record| record.attempts += 1);
                if self.failures_left > 0 {
                    self.failures_left -= 1;
                    self.sink.failed(self.control.kind(), unavailable());
                    return false;
                }
            }
            if let Err(error) = self.control.deny(&self.view) {
                self.sink.failed(self.control.kind(), error);
                return false;
            }
            self.denied = true;
            #[cfg(test)]
            match super::control_fixture::readback(&self.control) {
                Ok(denied) => super::control_fixture::update(self.observation, |record| {
                    record.readback = Some(denied);
                }),
                Err(error) => {
                    self.sink.failed(self.control.kind(), error);
                }
            }
        }
        let Some(deferral) = &self.deferral else {
            return true;
        };
        if self.completed {
            return false;
        }
        self.completed = true;
        #[cfg(test)]
        {
            super::control_fixture::update(self.observation, |record| record.completions += 1);
            if super::control_fixture::mode(self.control.kind())
                == crate::ControlFault::UncertainComplete
            {
                self.sink.failed(self.control.kind(), unavailable());
                return false;
            }
        }
        match super::denial::complete_request(deferral) {
            Ok(()) => true,
            Err(error) => {
                self.sink.failed(self.control.kind(), error);
                false
            }
        }
    }
}

#[cfg(test)]
impl Drop for Held {
    fn drop(&mut self) {
        super::control_fixture::update(self.observation, |record| record.retired = true);
    }
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use super::Control;
    use crate::{EventKind, Failure, NativeError, Operation};

    #[test]
    fn modeled_missing_control_arguments_refuse_deferral_before_native_access() {
        for (control, kind) in [
            (Control::NewWindow(None), EventKind::NewWindow),
            (Control::Permission(None), EventKind::Permission),
            (Control::Download(None), EventKind::Download),
            (Control::External(None), EventKind::ExternalUri),
            (Control::Authentication(None), EventKind::Authentication),
        ] {
            assert_eq!(control.kind(), kind);
            assert_eq!(
                control.defer().err(),
                Some(NativeError {
                    operation: Operation::Subscription,
                    failure: Failure::CallFailed,
                })
            );
        }
        let navigation = Control::Navigation { _args: None };
        assert_eq!(navigation.kind(), EventKind::Navigation);
        assert_eq!(
            navigation.defer().map(|deferral| deferral.is_none()),
            Ok(true)
        );
    }
}
