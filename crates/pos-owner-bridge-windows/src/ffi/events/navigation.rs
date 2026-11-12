#![cfg(windows)]

use super::control_denial::Control;
use super::{action, observe, unavailable, Recovery, Result, Subscriptions};
use crate::{EventKind, EventSink, NativeAction, NativeEvent, NativeText};
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
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    starting(view, signals, recovery, subscriptions)?;
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
    recovery: &Rc<Recovery>,
    subscriptions: &mut Subscriptions,
) -> Result<()> {
    let view: ICoreWebView2 = view.cast().map_err(|_| unavailable())?;
    let remove = view.clone();
    let observed = Rc::clone(signals);
    let cancellation = Rc::clone(recovery);
    let intercepted = view.clone();
    #[cfg(test)]
    let allow_reports = std::cell::Cell::new(0_u8);
    let handler = NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
        navigation_start(
            args,
            intercepted.clone(),
            Rc::clone(&observed),
            &cancellation,
            #[cfg(test)]
            &allow_reports,
        );
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
    // Capture the owning case now, not when a possibly late callback arrives.
    #[cfg(test)]
    let case = READINESS_CASE.with(std::cell::Cell::get);
    #[cfg(test)]
    let reports = std::cell::Cell::new(0_u8);
    let handler = NavigationCompletedEventHandler::create(Box::new(move |_sender, args| {
        let result = navigation_completed(args);
        #[cfg(test)]
        trace_completion("NATIVE_NAVIGATION_COMPLETED", case, &reports, &result);
        observe(observed.as_ref(), EventKind::NavigationCompleted, result);
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

// Bounded diagnostics for the subscription's original case and time origin.
#[cfg(test)]
fn trace_completion(
    prefix: &'static str,
    case: Option<(u64, std::time::Instant)>,
    reports: &std::cell::Cell<u8>,
    result: &Result<NativeEvent>,
) {
    use std::io::Write as _;
    let Some((case, started)) = case else {
        return;
    };
    let count = reports.get();
    if count >= 9 {
        return;
    }
    reports.set(count + 1);
    if count == 8 {
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "{prefix} case={case} elapsed={:?} overflow=true",
            started.elapsed()
        );
        return;
    }
    if let Ok(NativeEvent::NavigationCompleted { id, success }) = result {
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "{prefix} case={case} elapsed={:?} id={id} success={success}",
            started.elapsed()
        );
    } else {
        let _logged_or_unavailable = writeln!(
            std::io::stderr(),
            "{prefix} case={case} elapsed={:?} observation=unavailable",
            started.elapsed()
        );
    }
}

#[test]
fn readiness_completion_trace_is_bounded_and_disabled_without_a_case() {
    let reports = std::cell::Cell::new(0);
    let result = Ok(NativeEvent::NavigationCompleted {
        id: 2,
        success: true,
    });
    trace_completion("NATIVE_NAVIGATION_COMPLETED_UNIT", None, &reports, &result);
    assert_eq!(reports.get(), 0);
    let case = Some((42, std::time::Instant::now()));
    trace_completion(
        "NATIVE_NAVIGATION_COMPLETED_UNIT",
        case,
        &reports,
        &Err(unavailable()),
    );
    for _ in 0..12 {
        trace_completion("NATIVE_NAVIGATION_COMPLETED_UNIT", case, &reports, &result);
    }
    assert_eq!(reports.get(), 9);
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
    let handler = ProcessFailedEventHandler::create(Box::new(move |_sender, args| {
        #[cfg(test)]
        super::control_fixture::process_failed(args.as_ref());
        drop(args);
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

#[cfg(test)]
thread_local! {
    static READINESS_CASE: std::cell::Cell<Option<(u64, std::time::Instant)>> = const { std::cell::Cell::new(None) };
    static READINESS_OPERATIONS: std::cell::RefCell<std::collections::BTreeSet<&'static str>> = const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

#[cfg(test)]
pub(super) fn readiness_context() -> Option<(u64, std::time::Instant)> {
    READINESS_CASE.with(std::cell::Cell::get)
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn readiness_navigation_case(case: Option<(u64, std::time::Instant)>) {
        super::resource::reset_readiness_resource();
        READINESS_CASE.with(|current| current.set(case));
        READINESS_OPERATIONS.with(|operations| operations.borrow_mut().clear());
    }

    pub(crate) fn readiness_span(operation: &'static str) -> impl Drop {
        let case = READINESS_CASE.with(std::cell::Cell::get).filter(|_| {
            READINESS_OPERATIONS.with(|operations| operations.borrow_mut().insert(operation))
        });
        ReadinessSpan {
            operation,
            case,
            started: std::time::Instant::now(),
        }
    }
}

#[cfg(test)]
struct ReadinessSpan {
    operation: &'static str,
    case: Option<(u64, std::time::Instant)>,
    started: std::time::Instant,
}

#[cfg(test)]
impl Drop for ReadinessSpan {
    fn drop(&mut self) {
        if let Some((case, origin)) = self.case {
            use std::io::Write as _;
            let _logged_or_unavailable = writeln!(
                std::io::stderr(),
                "NATIVE_READINESS_OPERATION case={case} operation={} entered={:?} returned={:?} duration={:?}",
                self.operation,
                self.started.saturating_duration_since(origin),
                origin.elapsed(),
                self.started.elapsed(),
            );
        }
    }
}

fn navigation_start(
    args: Option<ICoreWebView2NavigationStartingEventArgs>,
    view: ICoreWebView2,
    sink: Rc<dyn EventSink>,
    recovery: &Recovery,
    #[cfg(test)] allow_reports: &std::cell::Cell<u8>,
) {
    let Some(args) = args else {
        sink.failed(EventKind::Navigation, unavailable());
        recovery.control(Control::Navigation { _args: None }, view, sink);
        return;
    };
    let result = navigation_snapshot(&args);
    let selected = observe(sink.as_ref(), EventKind::Navigation, result);
    let allow = selected == NativeAction::Allow;
    if !allow {
        action(
            sink.as_ref(),
            EventKind::Navigation,
            selected,
            NativeAction::Cancel,
        );
    }
    // SAFETY: live invoking-STA arguments; only the safe policy can select Allow.
    let set_cancel = unsafe { args.SetCancel(!allow) };
    #[cfg(test)]
    if allow && allow_reports.get() < 16 {
        use std::io::Write as _;
        allow_reports.set(allow_reports.get() + 1);
        READINESS_CASE.with(|current| {
            if let Some((case, started)) = current.get() {
                let _logged_or_unavailable = writeln!(
                    std::io::stderr(),
                    "NATIVE_NAVIGATION_ALLOW case={case} elapsed={:?} success={}",
                    started.elapsed(),
                    set_cancel.is_ok()
                );
            }
        });
    }
    if set_cancel.is_err() {
        sink.failed(EventKind::Navigation, unavailable());
        if !allow {
            recovery.control(Control::Navigation { _args: Some(args) }, view, sink);
        }
    } else if !allow {
        #[cfg(test)]
        if let Err(error) = super::control_fixture::navigation(&args) {
            sink.failed(EventKind::Navigation, error);
        }
    }
}

fn navigation_snapshot(args: &ICoreWebView2NavigationStartingEventArgs) -> Result<NativeEvent> {
    super::super::text::read_text(|out| {
        // SAFETY: live arguments and helper-owned initialized writable string output.
        unsafe { args.Uri(out) }
    })
    .and_then(|uri| {
        let mut redirected = BOOL::default();
        // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
        unsafe { args.IsRedirected(&raw mut redirected) }
            .map_err(|_| unavailable())
            .and_then(|()| {
                let mut id = 0;
                // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
                unsafe { args.NavigationId(&raw mut id) }
                    .map_err(|_| unavailable())
                    .map(|()| NativeEvent::Navigation {
                        uri,
                        id,
                        redirected: redirected.as_bool(),
                    })
            })
    })
}

pub(in crate::ffi) fn source(view: &ICoreWebView2) -> Result<NativeText> {
    super::super::text::read_text(|out| {
        // SAFETY: retained live STA view and helper-owned initialized string output.
        unsafe { view.Source(out) }
    })
}

fn content_loading(args: Option<ICoreWebView2ContentLoadingEventArgs>) -> Result<NativeEvent> {
    args.ok_or_else(unavailable).and_then(|args| {
        let mut id = 0;
        // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
        unsafe { args.NavigationId(&raw mut id) }
            .map_err(|_| unavailable())
            .and_then(|()| {
                let mut error_page = BOOL::default();
                // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
                unsafe { args.IsErrorPage(&raw mut error_page) }
                    .map_err(|_| unavailable())
                    .map(|()| NativeEvent::Content {
                        id,
                        error_page: error_page.as_bool(),
                    })
            })
    })
}

fn dom_loaded(
    sender: Option<ICoreWebView2>,
    args: Option<ICoreWebView2DOMContentLoadedEventArgs>,
) -> Result<NativeEvent> {
    args.ok_or_else(unavailable).and_then(|args| {
        sender.ok_or_else(unavailable).and_then(|view| {
            let mut id = 0;
            // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
            unsafe { args.NavigationId(&raw mut id) }
                .map_err(|_| unavailable())
                .and_then(|()| source(&view).map(|uri| NativeEvent::DomLoaded { id, uri }))
        })
    })
}

fn navigation_completed(
    args: Option<ICoreWebView2NavigationCompletedEventArgs>,
) -> Result<NativeEvent> {
    args.ok_or_else(unavailable).and_then(|args| {
        let mut id = 0;
        // SAFETY: live invoking-STA arguments and initialized unique navigation-ID output.
        unsafe { args.NavigationId(&raw mut id) }
            .map_err(|_| unavailable())
            .and_then(|()| {
                let mut success = BOOL::default();
                // SAFETY: live invoking-STA arguments and initialized unique BOOL output.
                unsafe { args.IsSuccess(&raw mut success) }
                    .map_err(|_| unavailable())
                    .map(|()| NativeEvent::NavigationCompleted {
                        id,
                        success: success.as_bool(),
                    })
            })
    })
}

#[cfg(test)]
mod tests {
    #![forbid(unsafe_code)]

    use super::{content_loading, dom_loaded, navigation_completed};
    use crate::{Failure, NativeError, Operation};

    #[test]
    fn modeled_missing_navigation_arguments_refuse_before_native_access() {
        for result in [
            content_loading(None),
            dom_loaded(None, None),
            navigation_completed(None),
        ] {
            assert_eq!(
                result.err(),
                Some(NativeError {
                    operation: Operation::Subscription,
                    failure: Failure::CallFailed,
                })
            );
        }
    }
}
