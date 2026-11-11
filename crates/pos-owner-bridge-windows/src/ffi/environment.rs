#![cfg(windows)]

use crate::{
    EnvironmentSnapshot, EventKind, EventSink, Failure, NativeError, NativeEvent, NativeResult,
    Operation,
};
use std::rc::Rc;
use webview2_com::BrowserProcessExitedEventHandler;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2BrowserProcessExitedEventArgs, ICoreWebView2Environment,
    ICoreWebView2Environment12, ICoreWebView2Environment5, ICoreWebView2Environment7,
    ICoreWebView2EnvironmentOptions,
};
use windows::core::Interface;

type Result<T> = NativeResult<T>;

pub(super) struct Environment {
    pub(super) raw: ICoreWebView2Environment,
    exit: ICoreWebView2Environment5,
    token: Option<i64>,
    options: ICoreWebView2EnvironmentOptions,
}

impl Environment {
    pub(super) fn subscribe(
        raw: ICoreWebView2Environment,
        options: ICoreWebView2EnvironmentOptions,
        sink: &Rc<dyn EventSink>,
    ) -> Result<Self> {
        let exit: ICoreWebView2Environment5 = raw.cast().map_err(|_| unavailable())?;
        let observed = Rc::clone(sink);
        let callback = BrowserProcessExitedEventHandler::create(Box::new(move |_sender, args| {
            match browser_exited(args) {
                Ok(event) => {
                    #[cfg(test)]
                    if let NativeEvent::BrowserExited { pid } = &event {
                        crate::Native::record_callback(crate::NativeCallbackMoment::BrowserExit(
                            *pid,
                        ));
                    }
                    observed.event(event);
                }
                Err(error) => {
                    observed.failed(EventKind::BrowserExited, error);
                }
            }
            Ok(())
        }));
        let mut token = 0;
        // SAFETY: newly-created retained STA environment and live callback;
        // initialized unique token output, subscription precedes controller creation.
        unsafe { exit.add_BrowserProcessExited(&callback, &raw mut token) }
            .map_err(|_| unavailable())?;
        Ok(Self {
            raw,
            exit,
            token: Some(token),
            options,
        })
    }

    pub(super) fn snapshot(&self) -> Result<EnvironmentSnapshot> {
        let version = super::text::read_text(|out| {
            // SAFETY: retained STA environment and initialized helper-owned string output.
            unsafe { self.raw.BrowserVersionString(out) }
        })?;
        let environment7: ICoreWebView2Environment7 = self.raw.cast().map_err(|_| unavailable())?;
        let folder = super::text::read_path(|out| {
            // SAFETY: retained STA environment and initialized helper-owned string output.
            unsafe { environment7.UserDataFolder(out) }
        })?;
        let (arguments, options) = super::settings::observe_options(&self.options)?;
        Ok(EnvironmentSnapshot {
            version,
            folder,
            arguments,
            options,
        })
    }

    pub(super) fn shared(&self) -> Result<ICoreWebView2Environment12> {
        self.raw.cast().map_err(|_| unavailable())
    }

    pub(super) fn unsubscribe(&mut self) -> Result<()> {
        if let Some(token) = self.token {
            // SAFETY: exact retained environment and registration token on its
            // creating STA; successful removal is recorded before any retry.
            unsafe { self.exit.remove_BrowserProcessExited(token) }.map_err(|_| unavailable())?;
            self.token = None;
        }
        Ok(())
    }

    pub(super) const fn subscribed(&self) -> bool {
        self.token.is_some()
    }
}

fn browser_exited(args: Option<ICoreWebView2BrowserProcessExitedEventArgs>) -> Result<NativeEvent> {
    let args = args.ok_or_else(unavailable)?;
    let mut pid = 0;
    // SAFETY: retained invoking-STA arguments and initialized unique PID output.
    unsafe { args.BrowserProcessId(&raw mut pid) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::BrowserExited { pid })
}

const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Environment,
        failure: Failure::CallFailed,
    }
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use super::browser_exited;
    use crate::{Failure, NativeError, Operation};

    #[test]
    fn modeled_missing_browser_exit_arguments_refuse_before_native_access() {
        assert_eq!(
            browser_exited(None).err(),
            Some(NativeError {
                operation: Operation::Environment,
                failure: Failure::CallFailed,
            })
        );
    }
}
