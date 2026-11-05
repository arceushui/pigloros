#![cfg(windows)]

use super::{action, unavailable, Result, Subscriptions};
use crate::native_api::{EventKind, EventSink, NativeAction, NativeEvent};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2BasicAuthenticationRequestedEventArgs,
    ICoreWebView2DownloadStartingEventArgs, ICoreWebView2LaunchingExternalUriSchemeEventArgs,
    ICoreWebView2NewWindowRequestedEventArgs, ICoreWebView2PermissionRequestedEventArgs,
    ICoreWebView2_10, ICoreWebView2_18, ICoreWebView2_4, COREWEBVIEW2_PERMISSION_STATE_DENY,
};
use webview2_com::{
    BasicAuthenticationRequestedEventHandler, DownloadStartingEventHandler,
    LaunchingExternalUriSchemeEventHandler, NewWindowRequestedEventHandler,
    PermissionRequestedEventHandler, ScriptDialogOpeningEventHandler,
    WindowCloseRequestedEventHandler,
};
use windows::core::Interface;

pub(super) fn install(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    new_window(view, signals, subscriptions)?;
    permission(view, signals, subscriptions)?;
    download(view, signals, subscriptions)?;
    external(view, signals, subscriptions)?;
    authentication(view, signals, subscriptions)?;
    dialog(view, signals, subscriptions)?;
    close_request(view, signals, subscriptions)
}

fn new_window(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = NewWindowRequestedEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::NewWindow);
        action(
            observed.as_ref(),
            EventKind::NewWindow,
            selected,
            NativeAction::Handled,
        );
        if let Err(error) = block_new_window(args) {
            observed.failed(EventKind::NewWindow, error);
        }
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; initialized token output, retained by Subscriptions.
            unsafe { view.add_NewWindowRequested(&handler, token) }
        },
        move |token| {
            // SAFETY: this exact token belongs to the retained live interface on its creating STA.
            unsafe { remove.remove_NewWindowRequested(token) }
        },
    )
}

fn block_new_window(args: Option<ICoreWebView2NewWindowRequestedEventArgs>) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live event arguments on the invoking STA; fixed fail-closed setting.
    unsafe { args.SetHandled(true) }.map_err(|_| unavailable())
}

fn permission(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = PermissionRequestedEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::Permission);
        action(
            observed.as_ref(),
            EventKind::Permission,
            selected,
            NativeAction::Deny,
        );
        if let Err(error) = block_permission(args) {
            observed.failed(EventKind::Permission, error);
        }
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; initialized token output, retained by Subscriptions.
            unsafe { view.add_PermissionRequested(&handler, token) }
        },
        move |token| {
            // SAFETY: this exact token belongs to the retained live interface on its creating STA.
            unsafe { remove.remove_PermissionRequested(token) }
        },
    )
}

fn block_permission(args: Option<ICoreWebView2PermissionRequestedEventArgs>) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live event arguments on the invoking STA; fixed fail-closed setting.
    unsafe { args.SetState(COREWEBVIEW2_PERMISSION_STATE_DENY) }.map_err(|_| unavailable())
}

fn download(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_4 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = DownloadStartingEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::Download);
        action(
            observed.as_ref(),
            EventKind::Download,
            selected,
            NativeAction::Cancel,
        );
        if let Err(error) = block_download(args) {
            observed.failed(EventKind::Download, error);
        }
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; initialized token output, retained by Subscriptions.
            unsafe { view.add_DownloadStarting(&handler, token) }
        },
        move |token| {
            // SAFETY: this exact token belongs to the retained live interface on its creating STA.
            unsafe { remove.remove_DownloadStarting(token) }
        },
    )
}

fn block_download(args: Option<ICoreWebView2DownloadStartingEventArgs>) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live event arguments on the invoking STA; fixed fail-closed setting.
    unsafe { args.SetCancel(true) }.map_err(|_| unavailable())
}

fn external(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_18 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::ExternalUri);
        action(
            observed.as_ref(),
            EventKind::ExternalUri,
            selected,
            NativeAction::Cancel,
        );
        if let Err(error) = block_external(args) {
            observed.failed(EventKind::ExternalUri, error);
        }
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; initialized token output, retained by Subscriptions.
            unsafe { view.add_LaunchingExternalUriScheme(&handler, token) }
        },
        move |token| {
            // SAFETY: this exact token belongs to the retained live interface on its creating STA.
            unsafe { remove.remove_LaunchingExternalUriScheme(token) }
        },
    )
}

fn block_external(args: Option<ICoreWebView2LaunchingExternalUriSchemeEventArgs>) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live event arguments on the invoking STA; fixed fail-closed setting.
    unsafe { args.SetCancel(true) }.map_err(|_| unavailable())
}

fn authentication(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_10 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler =
        BasicAuthenticationRequestedEventHandler::create(Box::new(move |_sender, args| {
            let selected = observed.event(NativeEvent::Authentication);
            action(
                observed.as_ref(),
                EventKind::Authentication,
                selected,
                NativeAction::Cancel,
            );
            if let Err(error) = block_authentication(args) {
                observed.failed(EventKind::Authentication, error);
            }
            Ok(())
        }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler; initialized token output, retained by Subscriptions.
            unsafe { view.add_BasicAuthenticationRequested(&handler, token) }
        },
        move |token| {
            // SAFETY: this exact token belongs to the retained live interface on its creating STA.
            unsafe { remove.remove_BasicAuthenticationRequested(token) }
        },
    )
}

fn block_authentication(
    args: Option<ICoreWebView2BasicAuthenticationRequestedEventArgs>,
) -> Result<()> {
    let args = args.ok_or_else(unavailable)?;
    // SAFETY: live event arguments on the invoking STA; fixed fail-closed setting.
    unsafe { args.SetCancel(true) }.map_err(|_| unavailable())
}

fn dialog(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = ScriptDialogOpeningEventHandler::create(Box::new(move |_sender, _args| {
        // AreDefaultScriptDialogsEnabled is read back false. Not accepting and
        // taking no deferral dismisses this attempted dialog without showing UI.
        observed.event(NativeEvent::ScriptDialog);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized token output.
            unsafe { view.add_ScriptDialogOpening(&handler, token) }
        },
        move |token| {
            // SAFETY: matching token on the retained interface's creating STA.
            unsafe { remove.remove_ScriptDialogOpening(token) }
        },
    )
}

fn close_request(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = WindowCloseRequestedEventHandler::create(Box::new(move |_sender, _args| {
        observed.event(NativeEvent::CloseRequested);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized token output.
            unsafe { view.add_WindowCloseRequested(&handler, token) }
        },
        move |token| {
            // SAFETY: matching token on the retained interface's creating STA.
            unsafe { remove.remove_WindowCloseRequested(token) }
        },
    )
}
