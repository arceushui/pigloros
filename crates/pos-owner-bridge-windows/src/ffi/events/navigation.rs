#![cfg(windows)]

use super::{action, observe, unavailable, Result, Subscriptions};
use crate::native_api::{EventKind, EventSink, NativeAction, NativeEvent, NativeText};
use std::rc::Rc;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2, ICoreWebView2ContentLoadingEventArgs, ICoreWebView2DOMContentLoadedEventArgs,
    ICoreWebView2NavigationCompletedEventArgs, ICoreWebView2NavigationStartingEventArgs,
    ICoreWebView2_2, ICoreWebView2_4,
};
use webview2_com::{
    ContentLoadingEventHandler, DOMContentLoadedEventHandler, FrameCreatedEventHandler,
    NavigationCompletedEventHandler, NavigationStartingEventHandler, ProcessFailedEventHandler,
    SourceChangedEventHandler,
};
use windows::core::{Interface, BOOL};

pub(super) fn install(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    starting(view, signals, subscriptions)?;
    source_changed(view, signals, subscriptions)?;
    content(view, signals, subscriptions)?;
    loaded(view, signals, subscriptions)?;
    completed(view, signals, subscriptions)?;
    frame(view, signals, subscriptions)?;
    process(view, signals, subscriptions)
}

fn starting(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
        navigation_start(args, observed.as_ref());
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_NavigationStarting(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_NavigationStarting(token) }
        },
    )
}

fn source_changed(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = SourceChangedEventHandler::create(Box::new(move |sender, _args| {
        let result = sender
            .ok_or_else(unavailable)
            .and_then(|view| source(&view))
            .map(|uri| NativeEvent::Source { uri });
        observe(observed.as_ref(), EventKind::Source, result);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_SourceChanged(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_SourceChanged(token) }
        },
    )
}

fn content(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = ContentLoadingEventHandler::create(Box::new(move |_sender, args| {
        observe(observed.as_ref(), EventKind::Content, content_loading(args));
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_ContentLoading(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_ContentLoading(token) }
        },
    )
}

fn loaded(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = DOMContentLoadedEventHandler::create(Box::new(move |sender, args| {
        observe(
            observed.as_ref(),
            EventKind::DomLoaded,
            dom_loaded(sender, args),
        );
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_DOMContentLoaded(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_DOMContentLoaded(token) }
        },
    )
}

fn completed(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = NavigationCompletedEventHandler::create(Box::new(move |_sender, args| {
        observe(
            observed.as_ref(),
            EventKind::NavigationCompleted,
            navigation_completed(args),
        );
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_NavigationCompleted(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_NavigationCompleted(token) }
        },
    )
}

fn frame(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2_4 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = FrameCreatedEventHandler::create(Box::new(move |_sender, _args| {
        observed.event(NativeEvent::Frame);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_FrameCreated(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_FrameCreated(token) }
        },
    )
}

fn process(
    view: &ICoreWebView2,
    signals: &Rc<dyn EventSink>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let handler = ProcessFailedEventHandler::create(Box::new(move |_sender, _args| {
        observed.event(NativeEvent::ProcessFailed);
        Ok(())
    }));
    subscriptions.register(
        |token| {
            // SAFETY: live STA interface/handler and initialized unique token output.
            unsafe { view.add_ProcessFailed(&handler, token) }
        },
        move |token| {
            // SAFETY: exact registered token on its retained creating-STA interface.
            unsafe { remove.remove_ProcessFailed(token) }
        },
    )
}

fn navigation_start(args: Option<ICoreWebView2NavigationStartingEventArgs>, sink: &dyn EventSink) {
    let Some(args) = args else {
        sink.failed(EventKind::Navigation, unavailable());
        return;
    };
    let result = navigation_snapshot(&args);
    let selected = observe(sink, EventKind::Navigation, result);
    let allow = selected == NativeAction::Allow;
    if !allow {
        action(sink, EventKind::Navigation, selected, NativeAction::Cancel);
    }
    // SAFETY: live invoking-STA arguments; only the safe policy can select Allow.
    if unsafe { args.SetCancel(!allow) }.is_err() {
        sink.failed(EventKind::Navigation, unavailable());
    }
}

fn navigation_snapshot(args: &ICoreWebView2NavigationStartingEventArgs) -> Result<NativeEvent> {
    let uri = super::super::text::read_text(|out| {
        // SAFETY: live arguments and helper-owned initialized writable string output.
        unsafe { args.Uri(out) }
    })?;
    let mut redirected = BOOL::default();
    // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
    unsafe { args.IsRedirected(&raw mut redirected) }.map_err(|_| unavailable())?;
    let mut id = 0;
    // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
    unsafe { args.NavigationId(&raw mut id) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::Navigation {
        uri,
        id,
        redirected: redirected.as_bool(),
    })
}

pub(super) fn source(view: &ICoreWebView2) -> Result<NativeText> {
    super::super::text::read_text(|out| {
        // SAFETY: retained live STA view and helper-owned initialized string output.
        unsafe { view.Source(out) }
    })
}

fn content_loading(args: Option<ICoreWebView2ContentLoadingEventArgs>) -> Result<NativeEvent> {
    let args = args.ok_or_else(unavailable)?;
    let mut id = 0;
    // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
    unsafe { args.NavigationId(&raw mut id) }.map_err(|_| unavailable())?;
    let mut error_page = BOOL::default();
    // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
    unsafe { args.IsErrorPage(&raw mut error_page) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::Content {
        id,
        error_page: error_page.as_bool(),
    })
}

fn dom_loaded(
    sender: Option<ICoreWebView2>,
    args: Option<ICoreWebView2DOMContentLoadedEventArgs>,
) -> Result<NativeEvent> {
    let args = args.ok_or_else(unavailable)?;
    let view = sender.ok_or_else(unavailable)?;
    let mut id = 0;
    // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
    unsafe { args.NavigationId(&raw mut id) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::DomLoaded {
        id,
        uri: source(&view)?,
    })
}

fn navigation_completed(
    args: Option<ICoreWebView2NavigationCompletedEventArgs>,
) -> Result<NativeEvent> {
    let args = args.ok_or_else(unavailable)?;
    let mut id = 0;
    // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
    unsafe { args.NavigationId(&raw mut id) }.map_err(|_| unavailable())?;
    let mut success = BOOL::default();
    // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
    unsafe { args.IsSuccess(&raw mut success) }.map_err(|_| unavailable())?;
    Ok(NativeEvent::NavigationCompleted {
        id,
        success: success.as_bool(),
    })
}
