#![cfg(windows)]

use super::control_denial::Control;
use super::{action, unavailable, Recovery, Result, Subscriptions};
use crate::{EventKind, EventSink, NativeAction, NativeEvent};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2_10, ICoreWebView2_18, ICoreWebView2_4,
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
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    new_window(view, signals, recovery, subscriptions)?;
    permission(view, signals, recovery, subscriptions)?;
    download(view, signals, recovery, subscriptions)?;
    external(view, signals, recovery, subscriptions)?;
    authentication(view, signals, recovery, subscriptions)?;
    dialog(view, signals, subscriptions)?;
    close_request(view, signals, subscriptions)
}

fn new_window(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted: ICoreWebView2 = view.clone();
    let handler = NewWindowRequestedEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::NewWindow);
        action(
            observed.as_ref(),
            EventKind::NewWindow,
            selected,
            NativeAction::Handled,
        );
        cancellation.control(
            Control::NewWindow(args),
            intercepted.clone(),
            Rc::clone(&observed),
        );
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

fn permission(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted: ICoreWebView2 = view.clone();
    let handler = PermissionRequestedEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::Permission);
        action(
            observed.as_ref(),
            EventKind::Permission,
            selected,
            NativeAction::Deny,
        );
        cancellation.control(
            Control::Permission(args),
            intercepted.clone(),
            Rc::clone(&observed),
        );
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

fn download(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_4 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let handler = DownloadStartingEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::Download);
        action(
            observed.as_ref(),
            EventKind::Download,
            selected,
            NativeAction::Cancel,
        );
        cancellation.control(
            Control::Download(args),
            intercepted.clone(),
            Rc::clone(&observed),
        );
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

fn external(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_18 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let handler = LaunchingExternalUriSchemeEventHandler::create(Box::new(move |_sender, args| {
        let selected = observed.event(NativeEvent::ExternalUri);
        action(
            observed.as_ref(),
            EventKind::ExternalUri,
            selected,
            NativeAction::Cancel,
        );
        cancellation.control(
            Control::External(args),
            intercepted.clone(),
            Rc::clone(&observed),
        );
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

fn authentication(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_10 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let handler =
        BasicAuthenticationRequestedEventHandler::create(Box::new(move |_sender, args| {
            let selected = observed.event(NativeEvent::Authentication);
            action(
                observed.as_ref(),
                EventKind::Authentication,
                selected,
                NativeAction::Cancel,
            );
            cancellation.control(
                Control::Authentication(args),
                intercepted.clone(),
                Rc::clone(&observed),
            );
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
