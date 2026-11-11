#![cfg(windows)]

use crate::{
    BoolProperty, EnvironmentOptions, Failure, NativeError, NativeResult, NativeText, Operation,
};
use webview2_com::CoreWebView2EnvironmentOptions;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2Controller, ICoreWebView2Controller4,
    ICoreWebView2EnvironmentOptions, ICoreWebView2EnvironmentOptions2,
    ICoreWebView2EnvironmentOptions3, ICoreWebView2EnvironmentOptions6, ICoreWebView2Settings,
    ICoreWebView2Settings3, ICoreWebView2Settings4, ICoreWebView2Settings5, ICoreWebView2Settings6,
    ICoreWebView2Settings8,
};
use windows::core::{w, Interface, BOOL};

fn failed(_: windows::core::Error) -> NativeError {
    error(Failure::CallFailed)
}
fn missing(_: windows::core::Error) -> NativeError {
    error(Failure::MissingInterface)
}
const fn error(failure: Failure) -> NativeError {
    NativeError {
        operation: Operation::Settings,
        failure,
    }
}

fn settings(view: &ICoreWebView2) -> NativeResult<ICoreWebView2Settings> {
    // SAFETY: a retained live WebView on its creating STA; COM owns the returned interface.
    unsafe { view.Settings() }.map_err(failed)
}

pub(super) fn set_bool(
    view: &ICoreWebView2,
    controller: &ICoreWebView2Controller,
    property: BoolProperty,
    value: bool,
) -> NativeResult<()> {
    match property {
        BoolProperty::Script => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsScriptEnabled(value) }
        }
        BoolProperty::WebMessage => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsWebMessageEnabled(value) }
        }
        BoolProperty::ScriptDialogs => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAreDefaultScriptDialogsEnabled(value) }
        }
        BoolProperty::StatusBar => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsStatusBarEnabled(value) }
        }
        BoolProperty::DevTools => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAreDevToolsEnabled(value) }
        }
        BoolProperty::ContextMenus => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAreDefaultContextMenusEnabled(value) }
        }
        BoolProperty::HostObjects => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAreHostObjectsAllowed(value) }
        }
        BoolProperty::Zoom => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsZoomControlEnabled(value) }
        }
        BoolProperty::BuiltInErrorPage => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsBuiltInErrorPageEnabled(value) }
        }
        BoolProperty::BrowserAccelerators => {
            let property: ICoreWebView2Settings3 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAreBrowserAcceleratorKeysEnabled(value) }
        }
        BoolProperty::PasswordAutosave => {
            let property: ICoreWebView2Settings4 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsPasswordAutosaveEnabled(value) }
        }
        BoolProperty::Autofill => {
            let property: ICoreWebView2Settings4 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsGeneralAutofillEnabled(value) }
        }
        BoolProperty::PinchZoom => {
            let property: ICoreWebView2Settings5 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsPinchZoomEnabled(value) }
        }
        BoolProperty::SwipeNavigation => {
            let property: ICoreWebView2Settings6 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsSwipeNavigationEnabled(value) }
        }
        BoolProperty::ReputationChecking => {
            let property: ICoreWebView2Settings8 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetIsReputationCheckingRequired(value) }
        }
        BoolProperty::ExternalDrop => {
            let property: ICoreWebView2Controller4 = controller.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface; the bool is supplied by the safe policy.
            unsafe { property.SetAllowExternalDrop(value) }
        }
    }
    .map_err(failed)
}

pub(super) fn get_bool(
    view: &ICoreWebView2,
    controller: &ICoreWebView2Controller,
    property: BoolProperty,
) -> NativeResult<bool> {
    let mut value = BOOL::default();
    match property {
        BoolProperty::Script => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsScriptEnabled(&raw mut value) }
        }
        BoolProperty::WebMessage => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsWebMessageEnabled(&raw mut value) }
        }
        BoolProperty::ScriptDialogs => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AreDefaultScriptDialogsEnabled(&raw mut value) }
        }
        BoolProperty::StatusBar => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsStatusBarEnabled(&raw mut value) }
        }
        BoolProperty::DevTools => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AreDevToolsEnabled(&raw mut value) }
        }
        BoolProperty::ContextMenus => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AreDefaultContextMenusEnabled(&raw mut value) }
        }
        BoolProperty::HostObjects => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AreHostObjectsAllowed(&raw mut value) }
        }
        BoolProperty::Zoom => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsZoomControlEnabled(&raw mut value) }
        }
        BoolProperty::BuiltInErrorPage => {
            let property = settings(view)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsBuiltInErrorPageEnabled(&raw mut value) }
        }
        BoolProperty::BrowserAccelerators => {
            let property: ICoreWebView2Settings3 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AreBrowserAcceleratorKeysEnabled(&raw mut value) }
        }
        BoolProperty::PasswordAutosave => {
            let property: ICoreWebView2Settings4 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsPasswordAutosaveEnabled(&raw mut value) }
        }
        BoolProperty::Autofill => {
            let property: ICoreWebView2Settings4 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsGeneralAutofillEnabled(&raw mut value) }
        }
        BoolProperty::PinchZoom => {
            let property: ICoreWebView2Settings5 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsPinchZoomEnabled(&raw mut value) }
        }
        BoolProperty::SwipeNavigation => {
            let property: ICoreWebView2Settings6 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsSwipeNavigationEnabled(&raw mut value) }
        }
        BoolProperty::ReputationChecking => {
            let property: ICoreWebView2Settings8 = settings(view)?.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.IsReputationCheckingRequired(&raw mut value) }
        }
        BoolProperty::ExternalDrop => {
            let property: ICoreWebView2Controller4 = controller.cast().map_err(missing)?;
            // SAFETY: live same-STA typed interface and initialized uniquely writable BOOL.
            unsafe { property.AllowExternalDrop(&raw mut value) }
        }
    }
    .map_err(failed)?;
    Ok(value.as_bool())
}

pub(super) fn options(
    required: EnvironmentOptions,
) -> NativeResult<ICoreWebView2EnvironmentOptions> {
    let options: ICoreWebView2EnvironmentOptions = CoreWebView2EnvironmentOptions::default().into();
    // SAFETY: live unshared STA options and static empty browser arguments.
    unsafe { options.SetAdditionalBrowserArguments(w!("")) }.map_err(failed)?;
    let exclusive: ICoreWebView2EnvironmentOptions2 = options.cast().map_err(missing)?;
    // SAFETY: live typed STA options; value is selected by the safe environment policy.
    unsafe { exclusive.SetExclusiveUserDataFolderAccess(required.exclusive_folder) }
        .map_err(failed)?;
    let crash: ICoreWebView2EnvironmentOptions3 = options.cast().map_err(missing)?;
    // SAFETY: live typed STA options and caller-selected bounded boolean.
    unsafe { crash.SetIsCustomCrashReportingEnabled(required.custom_crash_reporting) }
        .map_err(failed)?;
    let extensions: ICoreWebView2EnvironmentOptions6 = options.cast().map_err(missing)?;
    // SAFETY: live typed STA options and caller-selected bounded boolean.
    unsafe { extensions.SetAreBrowserExtensionsEnabled(required.extensions) }.map_err(failed)?;
    Ok(options)
}

fn read_bool(read: impl FnOnce(*mut BOOL) -> windows::core::Result<()>) -> NativeResult<bool> {
    let mut value = BOOL::default();
    read(&raw mut value).map_err(failed)?;
    Ok(value.as_bool())
}

pub(super) fn observe_options(
    options: &ICoreWebView2EnvironmentOptions,
) -> NativeResult<(NativeText, EnvironmentOptions)> {
    let arguments = super::text::read_text(|out| {
        // SAFETY: live STA options and helper-owned initialized string output.
        unsafe { options.AdditionalBrowserArguments(out) }
    })?;
    let exclusive: ICoreWebView2EnvironmentOptions2 = options.cast().map_err(missing)?;
    let exclusive_folder = read_bool(|out| {
        // SAFETY: live typed STA options and helper-owned initialized BOOL output.
        unsafe { exclusive.ExclusiveUserDataFolderAccess(out) }
    })?;
    let crash: ICoreWebView2EnvironmentOptions3 = options.cast().map_err(missing)?;
    let custom_crash_reporting = read_bool(|out| {
        // SAFETY: live typed STA options and helper-owned initialized BOOL output.
        unsafe { crash.IsCustomCrashReportingEnabled(out) }
    })?;
    let extensions: ICoreWebView2EnvironmentOptions6 = options.cast().map_err(missing)?;
    let extensions = read_bool(|out| {
        // SAFETY: live typed STA options and helper-owned initialized BOOL output.
        unsafe { extensions.AreBrowserExtensionsEnabled(out) }
    })?;
    Ok((
        arguments,
        EnvironmentOptions {
            extensions,
            custom_crash_reporting,
            exclusive_folder,
        },
    ))
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use super::{missing, read_bool};
    use crate::{Failure, NativeError, Operation};
    use windows::core::{Error, HRESULT};

    #[test]
    fn settings_read_failures_keep_their_error_classification() {
        let error = Error::from_hresult(HRESULT(-1));
        assert_eq!(
            read_bool(|_| Err(error)),
            Err(NativeError {
                operation: Operation::Settings,
                failure: Failure::CallFailed,
            })
        );
        assert_eq!(
            missing(Error::from_hresult(HRESULT(-1))),
            NativeError {
                operation: Operation::Settings,
                failure: Failure::MissingInterface,
            }
        );
    }
}
