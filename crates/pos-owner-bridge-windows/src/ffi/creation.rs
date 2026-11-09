#![cfg(windows)]

use std::cell::RefCell;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::rc::Rc;

use webview2_com::Microsoft::Web::WebView2::Win32::{
    CreateCoreWebView2EnvironmentWithOptions, ICoreWebView2Controller,
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, ICoreWebView2Environment,
    ICoreWebView2EnvironmentOptions,
};
use webview2_com::{
    CreateCoreWebView2ControllerCompletedHandler, CreateCoreWebView2EnvironmentCompletedHandler,
};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{E_POINTER, HWND};

use crate::{EnvironmentOptions, Failure, NativeError, NativeResult, Operation};
type Result<T> = NativeResult<T>;
const fn unavailable() -> NativeError {
    NativeError {
        operation: Operation::Environment,
        failure: Failure::CallFailed,
    }
}

type Completion<T> = Rc<RefCell<Option<windows::core::Result<T>>>>;

pub(super) struct EnvironmentCreation {
    result: Completion<ICoreWebView2Environment>,
    // Keep every async input alive until completion, including on timeout.
    _runtime: HSTRING,
    _folder: HSTRING,
    pub(super) options: ICoreWebView2EnvironmentOptions,
    _callback: ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
}

impl EnvironmentCreation {
    pub(super) fn start(
        runtime: &Path,
        folder: &Path,
        required: EnvironmentOptions,
    ) -> Result<Self> {
        let runtime = path_string(runtime)?;
        let folder = path_string(folder)?;
        let options = super::settings::options(required)?;
        let result = Rc::new(RefCell::new(None));
        let completed = Rc::clone(&result);
        let callback =
            CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(move |hr, value| {
                #[cfg(test)]
                crate::Native::creation_moment(crate::NativeCreationMoment::EnvironmentCallback(
                    if hr.is_err() && value.is_some() {
                        crate::CreationCallback::Inconsistent
                    } else if hr.is_err() {
                        crate::CreationCallback::NativeFailure
                    } else if value.is_none() {
                        crate::CreationCallback::MissingInterface
                    } else {
                        crate::CreationCallback::Success
                    },
                ));
                let result = hr.and_then(|()| value.ok_or_else(|| E_POINTER.into()));
                #[cfg(test)]
                crate::Native::record_callback(crate::NativeCallbackMoment::EnvironmentCompletion(
                    result.is_ok(),
                ));
                *completed.borrow_mut() = Some(result);
                Ok(())
            }));
        // SAFETY: fixed verified runtime and fresh protected folder, live STA
        // options/callback, all UTF-16 inputs retained in this owner until completion.
        let call = unsafe {
            CreateCoreWebView2EnvironmentWithOptions(
                PCWSTR(runtime.as_ptr()),
                PCWSTR(folder.as_ptr()),
                &options,
                &callback,
            )
        };
        #[cfg(test)]
        crate::Native::creation_moment(crate::NativeCreationMoment::EnvironmentReturned(
            call.is_ok(),
        ));
        call.map_err(|_| unavailable())?;
        Ok(Self {
            result,
            _runtime: runtime,
            _folder: folder,
            options,
            _callback: callback,
        })
    }

    #[cfg(test)]
    pub(super) fn environment_succeeded(&self) -> Option<bool> {
        self.result
            .borrow()
            .as_ref()
            .map(std::result::Result::is_ok)
    }

    pub(super) fn take(&self) -> Option<Result<ICoreWebView2Environment>> {
        self.result
            .borrow_mut()
            .take()
            .map(|result| result.map_err(|_| unavailable()))
    }
}

pub(super) struct ControllerCreation {
    result: Completion<ICoreWebView2Controller>,
    _environment: ICoreWebView2Environment,
    _callback: ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
}

impl ControllerCreation {
    pub(super) fn start(environment: &ICoreWebView2Environment, hwnd: HWND) -> Result<Self> {
        let result = Rc::new(RefCell::new(None));
        let completed = Rc::clone(&result);
        let callback =
            CreateCoreWebView2ControllerCompletedHandler::create(Box::new(move |hr, value| {
                #[cfg(test)]
                crate::Native::creation_moment(crate::NativeCreationMoment::ControllerCallback(
                    if hr.is_err() && value.is_some() {
                        crate::CreationCallback::Inconsistent
                    } else if hr.is_err() {
                        crate::CreationCallback::NativeFailure
                    } else if value.is_none() {
                        crate::CreationCallback::MissingInterface
                    } else {
                        crate::CreationCallback::Success
                    },
                ));
                let result = hr.and_then(|()| value.ok_or_else(|| E_POINTER.into()));
                #[cfg(test)]
                crate::Native::record_callback(crate::NativeCallbackMoment::ControllerCompletion(
                    result.is_ok(),
                ));
                *completed.borrow_mut() = Some(result);
                Ok(())
            }));
        // SAFETY: retained live STA environment and callback; the surface keeps
        // its owned top-level HWND alive until this async operation completes.
        let call = unsafe { environment.CreateCoreWebView2Controller(hwnd, &callback) };
        #[cfg(test)]
        crate::Native::creation_moment(crate::NativeCreationMoment::ControllerReturned(
            call.is_ok(),
        ));
        call.map_err(|_| unavailable())?;
        Ok(Self {
            result,
            _environment: environment.clone(),
            _callback: callback,
        })
    }

    #[cfg(test)]
    pub(super) fn succeeded(&self) -> Option<bool> {
        self.result
            .borrow()
            .as_ref()
            .map(std::result::Result::is_ok)
    }

    pub(super) fn take(&self) -> Option<Result<ICoreWebView2Controller>> {
        self.result
            .borrow_mut()
            .take()
            .map(|result| result.map_err(|_| unavailable()))
    }
}

fn path_string(path: &Path) -> Result<HSTRING> {
    let units: Vec<_> = path.as_os_str().encode_wide().collect();
    if units.is_empty() || units.contains(&0) {
        return Err(unavailable());
    }
    Ok(HSTRING::from_wide(&units))
}
